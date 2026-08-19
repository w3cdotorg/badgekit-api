var dbm = require('db-migrate');
var type = dbm.dataType;
var async = require('async')

exports.up = function (db, callback) {
  async.series([
    db.runSql.bind(db, "ALTER TABLE `badgeInstances` ADD COLUMN `salt` VARCHAR(32) NULL"),
    db.runSql.bind(db, "ALTER TABLE `badgeInstances` ADD COLUMN `credential` MEDIUMTEXT NULL"),
    // add-nullable -> backfill -> tighten: give any pre-existing rows a
    // random salt before making the column NOT NULL.
    db.runSql.bind(db, "UPDATE `badgeInstances` SET `salt` = SUBSTRING(SHA2(CONCAT(RAND(), id), 256), 1, 16) WHERE `salt` IS NULL"),
    db.runSql.bind(db, "ALTER TABLE `badgeInstances` MODIFY `salt` VARCHAR(32) NOT NULL"),
  ], callback)
};

exports.down = function (db, callback) {
  async.series([
    db.runSql.bind(db, "ALTER TABLE `badgeInstances` DROP COLUMN `salt`"),
    db.runSql.bind(db, "ALTER TABLE `badgeInstances` DROP COLUMN `credential`"),
  ], callback)
};
