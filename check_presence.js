const admin = require('firebase-admin');

// Since this project might not have a service account key locally, 
// let's just use the REST API to fetch the document directly.

async function fetchDoc() {
    const res = await fetch('https://firestore.googleapis.com/v1/projects/interactivewithyou/databases/(default)/documents/overlayPresence/shekssink');
    const data = await res.json();
    console.log(JSON.stringify(data, null, 2));
}

fetchDoc().catch(console.error);
