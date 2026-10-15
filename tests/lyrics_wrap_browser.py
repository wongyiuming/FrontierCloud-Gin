"""Real Chromium layout: wrapping changes row height, never the font size."""
import argparse
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

def run(output):
    root = Path(__file__).resolve().parents[1]
    output.mkdir(parents=True, exist_ok=True)
    results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'], headless=True, args=['--no-sandbox'])
        try:
            for width,height in [(390,844),(768,1024),(1360,768)]:
                page=browser.new_page(viewport={'width':width,'height':height})
                page.set_content('<div id="inlineLyrics" style="position:absolute;top:0;left:0;right:0;bottom:auto;height:400px"><div class="sync-lyrics-lines"><div id="inlineLyricsTrack" class="sync-lyrics-track"></div></div></div><div id="fullscreenLyrics" class="fullscreen-lyrics hidden"><div class="fullscreen-lyrics-columns">'+''.join(f'<div class="fullscreen-lyrics-column" id="fullscreenLyricsColumn{i}"></div>' for i in range(3))+'</div></div>')
                page.add_style_tag(content=(root/'static/css/player.css').read_text())
                page.add_script_tag(content=(root/'static/js/player.js').read_text())
                page.evaluate("""() => {
                    activeLyricEntries=[{time:0,text:'上一句'},{time:1,text:'这是一句超过屏幕宽度的中文歌词需要自动换行并完整显示不能裁掉文字的顶部或底部'.repeat(2)},{time:2,text:'下一句'},{time:3,text:'再下一句'}];
                    renderLyricWindow(1);
                }""")
                facts=page.locator('.sync-lyric.current').evaluate("""row => {
                    const css=getComputedStyle(row), box=row.getBoundingClientRect();
                    const range=document.createRange(); range.selectNodeContents(row);
                    const fragments=[...range.getClientRects()];
                    return {fontSize:css.fontSize,height:box.height,scrollHeight:row.scrollHeight,clientHeight:row.clientHeight,scrollWidth:row.scrollWidth,clientWidth:row.clientWidth,lines:fragments.length,allTextInsideRow:fragments.every(r=>r.top>=box.top-1&&r.bottom<=box.bottom+1)};
                }""")
                assert facts['lines']>1 and facts['allTextInsideRow'], facts
                assert facts['scrollHeight']<=facts['clientHeight']+1 and facts['scrollWidth']<=facts['clientWidth']+1, facts
                before_font=facts['fontSize']
                page.evaluate('() => sizeSynchronizedLyrics()')
                assert page.locator('.sync-lyric.current').evaluate('(r)=>getComputedStyle(r).fontSize')==before_font
                page.screenshot(path=str(output/f'inline-lyrics-{width}.png'))
                page.evaluate('() => openFullscreenLyrics()')
                fullscreen=page.locator('.fullscreen-lyric-line').nth(1).evaluate('(r)=>({whiteSpace:getComputedStyle(r).whiteSpace,height:r.clientHeight,scroll:r.scrollHeight})')
                assert fullscreen['whiteSpace']=='normal' and fullscreen['scroll']<=fullscreen['height']+1, fullscreen
                page.screenshot(path=str(output/f'lyrics-{width}.png'))
                results.append({'viewport':[width,height],'inline':facts,'fullscreen':fullscreen})
                page.close()
        finally:browser.close()
    (output/'evidence.json').write_text(json.dumps({'real_chromium':True,'font_sizing_rules_unchanged':True,'layouts':results},ensure_ascii=False,indent=2),encoding='utf-8')
    print('PASS: long lyrics wrap at unchanged font sizing; no row clipping at mobile/tablet/desktop sizes')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);run(parser.parse_args().output)
