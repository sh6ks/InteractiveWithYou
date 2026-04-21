const fs = require('fs');
const html = fs.readFileSync('c:\\Users\\sheks\\Desktop\\InteractiveWithYou\\html\\overlay.html', 'utf8');
const scriptStart = html.indexOf('<script type="module">') + '<script type="module">'.length;
const scriptEnd = html.lastIndexOf('</script>');
const js = html.substring(scriptStart, scriptEnd);
fs.writeFileSync('c:\\Users\\sheks\\Desktop\\InteractiveWithYou\\overlay_script.js', js);
console.log('Extracted overlay_script.js');
