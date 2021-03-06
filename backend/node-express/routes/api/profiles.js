var router = require('express').Router();
var mongoose = require('mongoose');
var User = mongoose.model('User');
var auth = require('../auth');

router.param('username', function(req, res, next, username) {
    User.findOne({ username: username }).then(function(user) {
        if (!user) { return res.sendStatus(404); }

        req.profile = user;

        return next();
    }).catch(next);
});

// Retrieves user profile
router.get('/:username', auth.optional, function(req, res, next) {
    if (req.payload) {
        User.findById(req.payload.id).then(function(user) {
            if (!user) { return res.json({ profile: req.profile.toProfileJSONFor(false) }); }

            return res.json({ profile: req.profile.toProfileJSONFor(user) });
        });
    } else {
        return res.json({ profile: req.profile.toProfileJSONFor(false) });
    }
});

// Follow another user
router.post('/:username/follow', auth.required, function(req, res, next) {
    var profileId = req.profile._id;

    User.findById(req.payload.id).then(function(user) {
        if (!user) { return res.sendStatus(401); }

        return user.follow(profileId).then(function() {
            return res.json({ profile: req.profile.toProfileJSONFor(user) });
        });
    }).catch(next);
});

// Unfollow another user
router.delete('/:username/follow', auth.required, function(req, res, next) {
    var profileId = req.profile._id;

    User.findById(req.payload.id).then(function(user) {
        if (!user) { return res.sendStatus(401); }

        return user.unfollow(profileId).then(function() {
            return res.json({ profile: req.profile.toProfileJSONFor(user) });
        });
    }).catch(next);
});

module.exports = router;