const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const cors = require('cors');
const _ = require('lodash');


const app = express();

app.use(cors());


const server = require('http').createServer(app);
const io = require('socket.io').listen(server);

const { User } = require('./helpers/UserClass');

require('./socket/streams')(io, User, _);
require('./socket/private')(io);

const dbConfig = require('./config/secret');
const auth = require('./routes/authRoutes');
const posts = require('./routes/postRoutes');
const users = require('./routes/userRoutes');
const friends = require('./routes/friendsRoutes');
const message = require('./routes/messageRoutes');
/*
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header(
        'Access-Control-Allow-Methods',
        'GET',
        'POST',
        'DELETE',
        'PUT',
        'OPTIONS'
    );
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, Authorization'
    );
    next();
});
*/

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
// app.use(logger('dev'));

mongoose.Promise = global.Promise;
mongoose.connect(
    dbConfig.url,
    { useNewUrlParser: true }
);


app.use('/api/chatapp', auth);
app.use('/api/chatapp', posts);
app.use('/api/chatapp', users);
app.use('/api/chatapp', friends);
app.use('/api/chatapp', message);

server.listen(3000, () => {
    console.log('Running on port 3000');
})