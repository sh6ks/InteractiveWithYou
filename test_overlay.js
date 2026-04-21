const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();
  
  page.on('console', msg => {
    console.log(`[Browser Console] ${msg.type().toUpperCase()}: ${msg.text()}`);
  });
  
  page.on('pageerror', error => {
    console.log(`[Browser Error] ${error.message}`);
  });

  console.log('Navigating to overlay...');
  await page.goto('https://interactive-with-you.vercel.app/html/overlay.html?canal=shekssink&tipo=efectos&debug=1', {
    waitUntil: 'networkidle0',
    timeout: 30000
  });

  console.log('Page loaded, waiting 5 seconds...');
  await new Promise(r => setTimeout(r, 5000));
  
  const debugText = await page.evaluate(() => {
    const el = document.getElementById('debugHud');
    return el ? el.innerText : 'NO DEBUG HUD';
  });
  
  console.log('Debug HUD:', debugText);
  
  await browser.close();
})();
