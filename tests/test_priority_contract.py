"""Published API and image schemas must follow the current native model."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PriorityContractTests(unittest.TestCase):
    def test_priority_operations_and_bounds_are_published(self):
        document = json.loads((ROOT / 'protocol/v2/openapi.json').read_text())
        inventory = json.loads((ROOT / 'protocol/v2/http-routes.json').read_text())
        path = '/api/v1/media/admin/priority-order'
        self.assertEqual(set(document['paths'][path]), {'get', 'post'})
        self.assertEqual(set(next(row['methods'] for row in inventory if row['path'] == path)), {'GET', 'POST'})
        schemas = document['components']['schemas']
        source = (ROOT / 'internal/store/priority.go').read_text()
        bounds = {name: int(re.search(r'const Priority' + name + r' = (-?\d+)', source)[1]) for name in ('Minimum', 'Maximum')}
        for name, field in [('DirectoryPriorityChange', 'value'), ('MediaPriorityChange', 'value'), ('PriorityEntry', 'preference')]:
            value = schemas[name]['properties'][field]
            self.assertEqual((value['minimum'], value['maximum']), (bounds['Minimum'], bounds['Maximum']))
        move = schemas['PriorityMove']
        self.assertEqual(set(move['required']), {'scope', 'kind', 'revision', 'path'})
        self.assertEqual(set(move['properties']), {'scope', 'kind', 'revision', 'path', 'before', 'after'})
        self.assertEqual(schemas['PriorityOrder']['properties']['items']['items']['$ref'], '#/components/schemas/PriorityEntry')
        for method in ('get', 'post'):
            response = document['paths'][path][method]['responses']
            self.assertEqual(response['200']['content']['application/json']['schema']['$ref'], '#/components/schemas/PriorityOrder')
            self.assertTrue({'401', '403', '409', '422'} <= response.keys())

    def test_all_compilation_paths_and_manifest_match_current_generation(self):
        source = (ROOT / 'migrations/schema.go').read_text()
        generation = int(re.search(r'const Generation = (\d+)', source)[1])
        for name in ('Dockerfile', 'Dockerfile.gin', 'nginx/Dockerfile', 'updater/Dockerfile', 'updater/Dockerfile.gin',
                     'ci/Dockerfile.web', 'ci/Dockerfile.updater', 'tests/publication-oci.Dockerfile'):
            label = re.search(r'frontiercloud.schema-generation="(\d+)"', (ROOT / name).read_text())
            self.assertIsNotNone(label, name)
            self.assertEqual(int(label[1]), generation, name)
        from scripts.registry_images import SCHEMA_GENERATION
        self.assertEqual(int(SCHEMA_GENERATION), generation)
        schema = json.loads((ROOT / 'protocol/v2/schemas/release-manifest.json').read_text())
        self.assertEqual(schema['properties']['schema_generation']['const'], generation)
        vector = json.loads((ROOT / f'protocol/v2/vectors/release-manifest-generation{generation}.json').read_text())
        valid = [row for row in vector['cases'] if row['valid']]
        self.assertTrue(valid)
        for row in valid:
            self.assertEqual(row['manifest']['schema_generation'], generation)


if __name__ == '__main__':
    unittest.main()
