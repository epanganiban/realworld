var mongoose = require('mongoose');
var User = mongoose.model('User');
var uniqueValidator = require('mongoose-unique-validator');
var slug = require('slug');

var ArticleSchema = new mongoose.Schema({
    slug: { type: String, lowercase: true, unique: true },
    title: String,
    description: String,
    body: String,
    favoritesCount: { type: Number, default: 0 },
    tagList: [{ type: String }],
    comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });

ArticleSchema.plugin(uniqueValidator, { message: 'is already taken' });

// Generates article slug
ArticleSchema.methods.slugify = function() {
    this.slug = slug(this.title) + '-' + (Math.random() * Math.pow(36, 6) | 0).toString(36);
};

// Ensures slug gets generated before validation
ArticleSchema.pre('validate', function(next) {
    if (!this.slug) {
        this.slugify();
    }

    next();
});

// Gets JSON representation of Article
ArticleSchema.methods.toJSONFor = function(user) {
    return {
        slug: this.slug,
        title: this.title,
        description: this.description,
        body: this.body,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt,
        tagList: this.tagList,
        favorited: user ? user.isFavorite(this._id) : false,
        favoritesCount: this.favoritesCount,
        author: this.author.toProfileJSONFor(user)
    };
};

// Updates Article favorite count
ArticleSchema.methods.updateFavoriteCount = function() {
    var article = this;

    return User.count({ favorites: { $in: [article._id] } }).then(function(count) {
        article.favoritesCount = count;

        return article.save();
    });
};

mongoose.model('Article', ArticleSchema);