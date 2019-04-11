const httpStatus = require('http-status-codes');

const User = require('../models/userModels');

module.exports = {
    FollowUser(req, res) {
        const followUser = async () => {
            await User.update(
                {
                    _id: req.user._id,
                    'following.userFollowed': { $ne: req.body.userFollowed }
                },
                {
                    $push: {
                        following: {
                            userFollowed: req.body.userFollowed
                        }
                    }
                }
            );

            await User.update(
                {
                    _id: req.body.userFollowed,
                    'following.follower': { $ne: req.user._id }
                },
                {
                    $push: {
                        followers: {
                            follower: req.user._id
                        },
                        notifications: {
                            senderId: req.user._id,
                            message: `${req.user.username} is now follosing you.`,
                            created: new Date(),
                            viewProfile: false
                        }
                    }
                }
            );
        };

        followUser()
            .then(() => {
                res
                    .status(httpStatus.OK)
                    .json({ message: 'Following user now' });
            })
            .catch(err => {
                res
                    .status(httpStatus.INTERNAL_SERVER_ERROR)
                    .json({ message: 'Error occurred', err });
            });
    },

    UnFollowUser(req, res) {
        const unFollowUser = async () => {
            await User.update(
                {
                    _id: req.user._id
                },
                {
                    $pull: {
                        following: {
                            userFollowed: req.body.userFollowed
                        }
                    }
                }
            );

            await User.update(
                {
                    _id: req.body.userFollowed
                },
                {
                    $pull: {
                        followers: {
                            follower: req.user._id
                        }
                    }
                }
            );
        };

        unFollowUser()
            .then(() => {
                res
                    .status(httpStatus.OK)
                    .json({ message: 'unFollowing user now' });
            })
            .catch(err => {
                res
                    .status(httpStatus.INTERNAL_SERVER_ERROR)
                    .json({ message: 'Error occurred' });
            });
    },

    async MarkNotification(req, res) {
    //    console.log(req.body);
        if (!req.body.deleteValue) {
            await User.updateOne(
                {
                    _id: req.user._id,
                    'notifications._id': req.params.id
                },
                {
                    $set: { 'notifications.$.read': true }
                }
            )
                .then(() => {
                    res
                        .status(httpStatus.OK)
                        .json({ message: 'Marked as read' });
                })
                .catch(err => {
                    res
                        .status(httpStatus.INTERNAL_SERVER_ERROR)
                        .json({ message: 'Error occured' });
                })
        } else {
            await User.update(
                {
                    _id: req.user._id,
                    'notifications._id': req.params.id
                },
                {
                    $pull: {
                        notifications: { _id: req.params.id }
                    }
                }
            )
                .then(() => {
                    res.status(httpStatus.OK).json({ message: 'Deleted successfully' });
                })
                .catch(err => {
                    res.status(httpStatus.INTERNAL_SERVER_ERROR).json({ message: 'Error occured.' });
                });
        }
    },

    async MarkAllNotifications(req, res) {
        await User.update(
            {
                _id: req.user._id
            },
            {
                $set: {
                    'notifications.$[elem].read': true
                }
            },
            {
                arrayFilters: [{
                    'elem.read': false
                }],
                multi: true
            }
        )
            .then(() => {
                res
                    .status(httpStatus.OK)
                    .json({message: 'Deleted successfully.'});
            })
            .catch(err => {
                res
                    .status(httpStatus.INTERNAL_SERVER_ERROR)
                    .json({message: 'Error occure'});
            });
    }
};