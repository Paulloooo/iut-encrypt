const crypto = require('crypto');

const encryptPasswordSha1 = (password) => {
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');
  return sha1Hash;
};

const comparePasswordSha1 = (inputPassword, hashedPassword) => {
  const inputHash = encryptPasswordSha1(inputPassword);
  return inputHash === hashedPassword;
};

module.exports = {
  encryptPasswordSha1,
  comparePasswordSha1,
};
