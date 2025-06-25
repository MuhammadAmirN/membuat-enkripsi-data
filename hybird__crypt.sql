-- Database: `hybird_crypt`
CREATE TABLE `files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filename` varchar(255),
  `ciphertext` longblob,
  `encrypted_key` blob,
  `nonce` blob,
  `tag` blob,
  `user_id` int(11),
  PRIMARY KEY (`id`)
);

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100),
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
);
