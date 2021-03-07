const Migrations = artifacts.require("Migrations");
const SchnorrSECP256K1 = artifacts.require("SchnorrSECP256K1");

module.exports = function (deployer) {
  deployer.deploy(Migrations);
  deployer.deploy(SchnorrSECP256K1);
};
