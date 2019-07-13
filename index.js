const express = require('express');
const http = require('http');
const bodyParser  = require('body-parser');
const morgan = require('morgan');
const app = express();
const router = require('./router');
const mongoose = require('mongoose');

// DB Setup
const mongo_port = 27017;
mongoose.connect(`mongodb://localhost:${mongo_port}/auth`, { useNewUrlParser: true });

app.use(morgan('combined'));
app.use(bodyParser.json({ type: '*/*'}));
router(app);

const port = process.env.PORT || 3000;
const server = http.createServer(app);
server.listen(port);
console.log('listening on: ', port);
