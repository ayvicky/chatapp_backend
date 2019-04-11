const Joi = require('joi');
const HttpStatus = require('http-status-codes');

const User = require('../models/userModels');
const Helper = require('../helpers/helper');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const dbConfig = require('../config/secret');

module.exports = {
    async CreateUser(req, res) {
        //    console.log(req.body);

        const schema = Joi.object().keys({
            username: Joi.string()
                .min(5)
                .max(10)
                .required(),
            email: Joi.string().email().required(),
            password: Joi.string()
                .min(5)
                .required()
        });

        const { error, value } = Joi.validate(req.body, schema);
    //    console.log(value);
        if (error && error.details) {
            //    return res.status(500).json({message: error.details});
            return res.status(HttpStatus.BAD_REQUEST).json({ msg: error.details });
        }

        const userEmail = await User.findOne({ email: Helper.lowerCase(req.body.email) });
        if (userEmail) {
            return res
                .status(HttpStatus.CONFLICT)
                .json({ message: 'Email already exist' });
        }

        const userName = await User.findOne({ username: Helper.firstUpper(req.body.username) });
        if (userName) {
            return res
                .status(HttpStatus.CONFLICT)
                .json({ message: 'Username already exist' });
        }

        return bcrypt.hash(value.password, 10, (error, hash) => {
            if (error) {
                return res
                    .status(HttpStatus.BAD_REQUEST)
                    .json({ message: 'Error hashing password.' });
            }
            const body = {
                username: Helper.firstUpper(value.username),
                email: Helper.lowerCase(value.email),
                password: hash
            };
            User.create(body)
                .then(user => {
                    const token = jwt.sign({ data: user }, dbConfig.secret, {
                        expiresIn: "1h"
                    });
                    res.cookie('auth', token);
                    res
                        .status(HttpStatus.CREATED)
                        .json({ message: 'User created successfully', user, token });
                })
                .catch(err => {
                    res
                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .json({ message: 'Error occured' });
                });
        });
    },

    async LoginUser(req, res) {
        if (!req.body.username || !req.body.password) {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ message: 'No empty fields allowed.' });
        }

        //check if user exist
        await User.findOne({ username: Helper.firstUpper(req.body.username) }).then((user) => {
            if (!user) {
                return res
                    .status(HttpStatus.NOT_FOUND)
                    .json({ message: 'username not found.' });
            }

            return bcrypt.compare(req.body.password, user.password).then((result) => {
                if (!result) {
                    return res
                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .json({ message: 'password is incorrect.' });
                }

                const token = jwt.sign({data: user}, dbConfig.secret, {
                    expiresIn: "1h"
                });
                res.cookie('auth', token);
                return res
                        .status(HttpStatus.OK)
                        .json({message: 'Login successful', user, token});
            })

        })
            .catch(err => {
                return res
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .json({ message: 'Error occurred.' });
            })
    }
};