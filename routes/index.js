const express = require('express');
const router = express.Router();
const webhookRouter = require('./webhook');


router.use('/webhook', webhookRouter);

module.exports = router;
