const tmi = require('tmi.js');

// Configure el cliente 
const client = new tmi.Client({
    channels: [ 'shekssink' ] 
});

// Conecte con los servidores de Twitch
client.connect().catch(console.error);

// Le indique qué hacer cuando alguien manda un mensaje
client.on('message', (channel, tags, message, self) => {
    // tags['display-name'] para obetner el nombre del usuario y el mensaje
    console.log(`${tags['display-name']} dice: ${message}`);
});