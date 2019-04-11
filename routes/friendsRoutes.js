const express = require('express');

const router = express.Router();

const FriendsCtrl = require('../controllers/friends');
const AuthHelper = require('../helpers/AuthHelper');

router.post('/follow-user', AuthHelper.VerifyToken, FriendsCtrl.FollowUser);
router.post('/unfollow-user', AuthHelper.VerifyToken, FriendsCtrl.UnFollowUser);
router.post('/mark/:id', AuthHelper.VerifyToken, FriendsCtrl.MarkNotification);
router.post('/mark-all', AuthHelper.VerifyToken, FriendsCtrl.MarkAllNotifications);

module.exports = router;