var mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;

var UserSchema = new mongoose.Schema({
    username: {
        type: String,
        lowercase: true,
        unique: true,
        required: [true, "can't be blank"],
        match: [/^[a-zA-Z0-9]+$/, 'is invalid'],
        index: true
    },
    email: {
        type: String,
        lowercase: true,
        unique: true,
        required: [true, "can't be blank"],
        match: [/\S+@\S+\.\S+/, 'is invalid'],
        index: true
    },
    bio: String,
    image: String,
    favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Article' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    hash: String,
    salt: String
}, { timestamps: true });

// Validate if user/email is unique
UserSchema.plugin(uniqueValidator, { message: 'is already taken.' });

// Hash password when setting
UserSchema.methods.setPassword = function(password) {
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
};

// Check hashes match when validating
UserSchema.methods.validPassword = function(password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
    return this.hash === hash;
};

// Generates a JSON Web Token
UserSchema.methods.generateJWT = function() {
    var today = new Date();
    var exp = new Date(today);
    exp.setDate(today.getDate() + 60);

    return jwt.sign({
        id: this._id,
        username: this.username,
        exp: parseInt(exp.getTime() / 1000),
    }, secret);
};

// Gets JSON representation of user
UserSchema.methods.toAuthJSON = function() {
    return {
        username: this.username,
        email: this.email,
        token: this.generateJWT(),
        bio: this.bio,
        image: this.image
    };
};

// Gets JSON representation of user profile
UserSchema.methods.toProfileJSONFor = function(user) {
    return {
        username: this.username,
        bio: this.bio,
        image: this.image || 'https://static.productionready.io/images/smiley-cyrus.jpg',
        following: user ? user.isFollowing(this._id) : false
    };
};

// Method for user to favorite an article
UserSchema.methods.favorite = function(id) {
    if (this.favorites.indexOf(id) === -1) {
        this.favorites.push(id);
    }

    return this.save();
};

// Method to remove article from user favorites
UserSchema.methods.unfavorite = function(id) {
    this.favorites.remove(id);
    return this.save();
};

// Method to check if user has favorited an article
UserSchema.methods.isFavorite = function(id) {
    return this.favorites.some(function(favoriteId) {
        if (favoriteId === null) { return false; }

        return favoriteId.toString() === id.toString();
    });
};

// Method for following another user
UserSchema.methods.follow = function(id) {
    if (this.following.indexOf(id) === -1) {
        this.following.push(id);
    }

    return this.save();
};

// Method for unfollowing another user
UserSchema.methods.unfollow = function(id) {
    this.following.remove(id);
    return this.save();
};

// Method for checking if user is following another user
UserSchema.methods.isFollowing = function(id) {
    return this.following.some(function(followId) {
        if (followId === null) { return false; }

        return followId.toString() === id.toString();
    });
};

mongoose.model('User', UserSchema);