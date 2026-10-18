"""Real Chromium layout check using shipped player markup and styles, no media I/O."""
import argparse
import json
import os
import re
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
TITLE = '黄耀明/MULTIVERSE_OF_GO_EAST_30TH_ANNIV'

def measure(page, kind, css):
    markup = (ROOT / f'static/media/{kind}-player.html').read_text()
    markup = re.sub(r'<script\b[^>]*>.*?</script>', '', markup, flags=re.S)
    markup = re.sub(r'<link\b[^>]*>', '', markup)
    markup = markup.replace('<head>', '<head><style>' + css + '</style>')
    markup = markup.replace('<span>四大发明</span>', '<span>' + TITLE + '</span>')
    markup = markup.replace('{{CATEGORY_LIST_URL}}', 'https://player-header.fixture.invalid/category')
    page.set_content(markup)
    header = page.locator('.sidebar-header')
    # Video uses the same header template but substitutes the business title at runtime.
    if kind == 'video':
        header.locator('span').first.evaluate('(e,title)=>e.textContent=title', TITLE)
    return header.evaluate('''header => {
      const title=header.firstElementChild, actions=header.querySelector('.header-actions');
      const button=actions.querySelector('a'), h=header.getBoundingClientRect(), b=button.getBoundingClientRect(), t=title.getBoundingClientRect();
      const sidebar=header.parentElement.getBoundingClientRect();
      return {title:title.textContent, font:getComputedStyle(title).fontSize,
        button:{x:b.x,right:b.right,y:b.y,bottom:b.bottom,width:b.width,height:b.height},
        header:{x:h.x,right:h.right,y:h.y,bottom:h.bottom},sidebar:{x:sidebar.x,right:sidebar.right},
        fits:b.left>=sidebar.left && b.right<=sidebar.right && b.top>=h.top && b.bottom<=h.bottom,
        overlap:Math.min(b.right,t.right)>Math.max(b.left,t.left) && Math.min(b.bottom,t.bottom)>Math.max(b.top,t.top)};
    }''')

def run(output, baseline):
    output.mkdir(parents=True, exist_ok=True)
    current=(ROOT/'static/css/player.css').read_text()
    result=[]
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE'], headless=True, args=['--no-sandbox'])
        for kind,width,height in [('audio',1360,768),('audio',390,844),('audio',320,640),('audio',844,390),('video',1360,768)]:
            page=browser.new_page(viewport={'width':width,'height':height})
            before=measure(page,kind,baseline.read_text()) if baseline else None
            after=measure(page,kind,current)
            assert after['fits'] and not after['overlap'],after
            assert TITLE==after['title'] and after['font']=='16px',after
            assert page.get_by_role('link',name='返回分类').get_attribute('href')=='https://player-header.fixture.invalid/category'
            page.screenshot(path=str(output/f'{kind}-{width}.png'))
            result.append({'kind':kind,'viewport':[width,height],'before':before,'after':after})
            page.close()
        browser.close()
    (output/'result.json').write_text(json.dumps({'passed':True,'scope':'shipped player header geometry; no playback claim','cases':result},indent=2,ensure_ascii=False))
    print('PASS: long album header keeps return link in bounds at desktop/mobile widths without font changes')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--baseline-css',type=Path)
    args=parser.parse_args();run(args.output,args.baseline_css)
