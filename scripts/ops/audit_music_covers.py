"""Read-only source-tag, catalog and cover-byte audit for test music imports.

Uses independent Mutagen and Pillow parsers on the operator/test host only.
Neither package is a product runtime dependency. Never modifies music files.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

from mutagen.id3 import ID3
from PIL import Image


def audit(source, manifest, origin):
    imported = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("result") == "uploaded":
            imported[row["source"]] = row
    albums = {}
    source_images = {}
    for relative, row in imported.items():
        file = source / relative
        tags = ID3(file)
        album = str(PurePosixPath(row["path"]).parent)
        item = albums.setdefault(album, {"files": 0, "files_with_embedded_cover": 0,
            "picture_frames": 0, "external_picture_links": 0, "valid_images": 0,
            "source_image_hashes": set(), "source_errors": [], "catalog_tracks": 0,
            "served_cover_tracks": 0, "category_has_cover": False, "problems": []})
        item["files"] += 1
        embedded = False
        source_images[row["path"]] = set()
        for picture in tags.getall("APIC"):
            item["picture_frames"] += 1
            if picture.mime == "-->":
                item["external_picture_links"] += 1
                continue
            embedded = True
            try:
                with Image.open(BytesIO(picture.data)) as image:
                    image.verify()
                item["valid_images"] += 1
                digest = hashlib.sha256(picture.data).hexdigest()
                item["source_image_hashes"].add(digest)
                source_images[row["path"]].add(digest)
            except Exception as error:
                item["source_errors"].append({"source": relative, "reason": str(error)})
        item["files_with_embedded_cover"] += embedded

    def get(route):
        # Catalog-returned artwork must stay on this environment's cover route.
        if not route.startswith("/api/v1/media/") or urlsplit(route).netloc:
            raise ValueError(f"Unexpected media route: {route}")
        with urlopen(origin.rstrip("/") + route, timeout=60) as response:
            return response.read(), response.headers.get("Content-Type", "")

    checked_covers = {}
    def check_cover(route, item, expected=None):
        if route not in checked_covers:
            content, content_type = get(route)
            if not content_type.startswith("image/"):
                raise ValueError("Cover response is not an image")
            with Image.open(BytesIO(content)) as image:
                image.verify()
            checked_covers[route] = hashlib.sha256(content).hexdigest()
        if checked_covers[route] not in (expected or item["source_image_hashes"]):
            raise ValueError("Cover bytes differ from this album's source artwork")

    for album, item in sorted(albums.items()):
        data, _ = get("/api/v1/media/catalog/media?" + urlencode({"media_type": "music",
            "path": album, "playback_session_id": "cover-audit"}))
        tracks = json.loads(data)["entries"]
        item["catalog_tracks"] = len(tracks)
        if len(tracks) != item["files"]:
            item["problems"].append("Catalog count differs from import manifest")
        for track in tracks:
            cover = track.get("cover", "")
            if not cover.startswith("/api/v1/media/cover?"):
                if source_images.get(track["media_path"]):
                    item["problems"].append({"path": track["media_path"], "reason": "Valid embedded artwork is missing"})
                continue
            try:
                check_cover(cover, item, source_images.get(track["media_path"]))
                item["served_cover_tracks"] += 1
            except Exception as error:
                item["problems"].append({"path": track["media_path"], "reason": str(error)})
        if item["valid_images"] and not item["served_cover_tracks"]:
            item["problems"].append("Valid source artwork is missing from the catalog")

    artists, _ = get("/api/v1/media/catalog/categories?media_type=music")
    for artist in json.loads(artists)["entries"]:
        page, _ = get(artist["url"])
        match = re.search(rb"window\.frontierCloudCatalogConfig\s*=\s*([^\n]+);", page)
        if not match:
            raise ValueError("Artist category page has no catalog configuration")
        for category in json.loads(match.group(1))["bootstrap"]:
            query = urlsplit(category["url"]).query
            album = parse_qs(query)["path"][0]
            if album not in albums:
                continue
            item = albums[album]
            cover = category.get("cover", "")
            item["category_has_cover"] = bool(cover)
            if cover:
                try:
                    check_cover(cover, item)
                except Exception as error:
                    item["problems"].append({"category_cover": cover, "reason": str(error)})
            elif item["valid_images"]:
                item["problems"].append("Valid source artwork is missing from the directory view")

    for item in albums.values():
        item["source_image_hashes"] = sorted(item["source_image_hashes"])
        item["status"] = ("problem" if item["problems"] or item["source_errors"]
                          else "source_has_no_embedded_artwork" if not item["files_with_embedded_cover"] else "verified")
    return {"files": len(imported), "albums": len(albums),
            "albums_without_embedded_artwork": sum(v["status"] == "source_has_no_embedded_artwork" for v in albums.values()),
            "albums_with_problems": sum(v["status"] == "problem" for v in albums.values()),
            "unique_cover_routes_verified": len(checked_covers), "details": albums}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.source, args.manifest, args.url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "details"}))
    raise SystemExit(1 if report["albums_with_problems"] else 0)
