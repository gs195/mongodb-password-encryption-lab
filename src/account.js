require("./db");
const crypto = require("crypto");
const mongoose = require("mongoose");
const generateSalt = () => crypto.randomBytes(32).toString("hex");

const userSchema = mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  salt: { type: String, required: true }
});

const UserModel = mongoose.model("User", userSchema);

const simpleSignUp = async input => {
  const newUser = new UserModel(input);
  return await newUser.save();
};

const simpleLogin = async input => {
  return await UserModel.findOne(input);
};

const hashSignUp = async input => {
  const hash = crypto.createHash("sha256");
  hash.update(input.password);
  const digest = hash.digest("hex");
  const userWithDigest = { username: input.username, password: digest };
  const newUser = new UserModel(userWithDigest);
  return await newUser.save();
};

const hashLogin = async input => {
  const hash = crypto.createHash("sha256");
  hash.update(input.password);
  const digest = hash.digest("hex");
  const userWithDigest = { username: input.username, password: digest };
  const foundUser = await UserModel.findOne(userWithDigest);
  if (foundUser) {
    return { username: foundUser.username };
  }
};

const hashSaltSignUp = async input => {
  const salt = generateSalt();
  const hash = crypto
    .createHmac("sha256", salt)
    .update(input.password)
    .digest("hex");
  const newUser = new UserModel({
    username: input.username,
    password: hash,
    salt: salt
  });
  return await newUser.save();
};

const hashSaltLogin = async input => {
  let foundUser;
  const foundUsers = await UserModel.find({
    username: input.username
  });
  foundUsers.forEach(elem => {
    const hash = crypto
      .createHmac("sha256", elem.salt)
      .update(input.password)
      .digest("hex");
    if (elem.password === hash) {
      foundUser = elem;
    }
  });
  if (foundUser) {
    return { username: foundUser.username };
  } else {
    return false;
  }
};

module.exports = {
  simpleSignUp,
  simpleLogin,
  hashSignUp,
  hashLogin,
  hashSaltSignUp,
  hashSaltLogin
};
