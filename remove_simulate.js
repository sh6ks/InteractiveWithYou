const fs = require('fs');
const file = 'c:/Users/sheks/Desktop/InteractiveWithYou/html/channel-points.html';
let data = fs.readFileSync(file, 'utf8');

// The start and end of the simulateRealRedeem function
const startStr = '        const simulateRealRedeem = async (rewardName) => {';
const endStr = '        document.getElementById(\'saveMediaBtn\').addEventListener(\'click\', async () => {';

const startIdx = data.indexOf(startStr);
const endIdx = data.indexOf(endStr);

if (startIdx !== -1 && endIdx !== -1) {
    data = data.substring(0, startIdx) + data.substring(endIdx);
    fs.writeFileSync(file, data);
    console.log('Successfully removed simulateRealRedeem');
} else {
    console.error('Could not find boundaries');
}
