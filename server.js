const express = require('express');
const path = require('path');
const bodyParser = require("body-parser");
const session = require('express-session');
const http = require('http');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(bodyParser.urlencoded({limit: '50mb', extended: false }));
app.use(bodyParser.json({limit: '50mb'}));
app.options(cors());
app.use(helmet());

const ControllerApi = require('./server/controller');
app.use('/api', ControllerApi);

app.use('/',express.static(path.join(__dirname, 'web')));
app.get('/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'web/index.html'));
});

app.use(function (err, req, res, next) {
	console.error(err);
	logger.log({
	  	level: 'error',
	  	time: (new Date()).toLocaleDateString('es-HN', {year:"numeric", month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", second:"2-digit"}),
	  	message: err
	});
  	res.status(500).send({title:"Error interno del servidor", message:"Revise su conexión de internet o inténtelo más tarde"});
})

const port = process.env.PORT || '8300';
app.set('port', port);
app.set('host', '0.0.0.0');
const server = http.createServer(app);
server.listen(port, () => console.log(`Running on 127.0.0.1:${port}`));

process.on('uncaughtException', function (err) {
	console.error(err);
    logger.log({
	  	level: 'error',
	  	time: (new Date()).toLocaleDateString('es-HN', {year:"numeric", month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", second:"2-digit"}),
	  	message: err
	});
}); 

const logger = winston.createLogger({
	level: 'info',
	format: winston.format.json(),
	defaultMeta: { service: 'user-service' },
	transports: [
	    new winston.transports.File({ filename: 'error.log' })
	]
});