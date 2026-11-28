"""Bounded Chromium response-stage faults for the signed synthetic AM2 fixture."""
from contextlib import contextmanager
from unittest.mock import patch

from a13_demo import UI, require, until
import a19_1_demo as prior
from a19_2_demo import quoted, start_observed_browser, upload_path


def start(args, scratch, stack):
    original = prior.visual_worker_script

    def instrument():
        script = original()
        declaration = 'let socket, seq = 0, clock = 0, origin;'
        listener = '      const p = message.params;'
        step = "  } else if (m.step === 'eval') {"
        require(all(script.count(anchor) == 1 for anchor in (declaration, listener, step)), 'Expected CDP fault hooks')
        return (script.replace(declaration, declaration + '\nlet lostPath, lostResponse;')
                .replace(listener, listener + r'''
      if (message.method === 'Fetch.requestPaused') {
        const url = new URL(p.request.url);
        const match = url.origin === origin && url.pathname === lostPath && p.request.method === 'POST';
        const id = p.requestId;
        if (match) {
          lostPath = undefined;
          const signal = {status:p.responseStatusCode, noStore:(p.responseHeaders ?? []).some(h=>
            h.name.toLowerCase()==='cache-control' && h.value.toLowerCase().split(',').map(s=>s.trim()).includes('no-store'))};
          void command('Fetch.failRequest',{requestId:id,errorReason:'ConnectionClosed'}).then(
            ()=>{lostResponse=signal;},()=>{lostResponse={error:true};});
        } else {
          void command('Fetch.continueRequest',{requestId:id}).catch(()=>note('UnexpectedInterception'));
        }
        return;
      }''').replace(step, '''  } else if (m.step === 'loseResponse') {
    lostPath=m.path; lostResponse=undefined;
    await command('Fetch.enable',{patterns:[{urlPattern:origin+m.path,requestStage:'Response'}]});
  } else if (m.step === 'lostResponse') {
    return {value:lostResponse};
  } else if (m.step === 'stopLosingResponse') {
    lostPath=undefined;
    await command('Fetch.disable',{});
''' + step))

    with patch.object(prior, 'visual_worker_script', instrument):
        return start_observed_browser(args, scratch, stack)


@contextmanager
def lose_response(browser, fmt):
    browser.run('loseResponse', path=upload_path(fmt))
    try:
        yield
    finally:
        browser.run('stopLosingResponse')


def assert_transport_loss(browser, mark, path):
    result = until(lambda: browser.run('lostResponse'), 'Chromium disconnected real bridge response', seconds=8)
    require(result == {'status': 202, 'noStore': True}, f'Chromium did not cut a real no-store bridge 202: {result}')
    failed = browser.receipt(mark, path, 202, method='POST', body=False, retired=True)
    require(failed.get('failed') and not failed.get('finished'), 'Chromium transport did not actually fail')


def malformed_client_receipt(browser, fmt):
    # The real response has already passed the actual bridge. Only the client
    # receives a different Response; capture the original receipt via AM1's
    # existing read-only observer. Never inspect or preserve request headers.
    browser.dom(f'''(() => {{
        const original = window.fetch.bind(window), expected = {quoted(UI + upload_path(fmt))};
        window.fetch = async (...args) => {{
            const response = await original(...args);
            if (response.url !== expected || args[1]?.method !== 'POST') return response;
            window.fetch = original;
            const value = await response.clone().json();
            if (response.status !== 202 || Object.keys(value).sort().join(',') !== 'id,state') return response;
            return new Response(JSON.stringify({{...value, unexpected: true}}), {{status:202,
                headers: {{'content-type':'application/json','cache-control':'private, no-store'}}}});
        }};
    }})()''')
