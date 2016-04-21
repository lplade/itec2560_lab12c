var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({
	local: {
		username: String,
		password: String
	},
	twitter: {
		id: String,
		token: String,
		displayName: String,
		username: String
	},
	favorites: [{
		date: String // YYYY-MM-DD
		//TODO validation function
	}]
});

userSchema.methods.generateHash = function(password){
	//Create salted hash of password by hashing plaintext password
	return bcrypt.hashSync(password, bcrypt.genSaltSync(8));
};

userSchema.methods.validPassword = function(password){
	//Hash entered password, compare with stored hash
	return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', userSchema);