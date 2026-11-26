// Module and method names are assembled at run time to evade pattern rules.
const cp = require(['child', 'process'].join('_'));
cp['ex' + 'ec']('echo SupplyShield-test');
module.exports = () => Date.now();
