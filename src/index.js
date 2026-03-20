const tmi = require('tmi.js');

// Configure el cliente para que escuche tu canal
const client = new tmi.Client({
    channels: [ 'shekssink' ] 
});

// Conecte a los servidores de Twitch
client.connect().catch(console.error);

// Le indique qué hacer cuando alguien manda un mensaje
client.on('message', (channel, tags, message, self) => {
    // tags['display-name'] trae el nombre del usuario y message el texto
    console.log(`${tags['display-name']} dice: ${message}`);
});