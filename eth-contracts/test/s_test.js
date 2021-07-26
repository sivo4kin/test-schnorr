const { expect, chai } = require("chai");
const web3 = require("web3");
const BN = web3.utils.BN

const log = console.log;
var exp = ethers.BigNumber.from("10").pow(18);

const hexToBN = s => new BN(s.replace(/^0[xX]/, ''), 16) // Construct BN from hex
const hexToStr = s => s.replace(/^0[xX]/, '')


const groupOrder = hexToBN(
    // Number of points in secp256k1
    '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
)
const gasUsage = new BN(1e6)

// Returns d as a 0x-hex string, left-padded with zeros to l bits.
const toHex = (d, l) =>
    // Make sure there's just one 0x prefix
    web3.utils.padLeft(d.toString(16), l / 4).replace(/^(0[xX])*/, '0x')

const bottom160bits = gasUsage.shln(160).sub(gasUsage)
const bottom256bits = gasUsage.shln(257).sub(gasUsage)


// Returns the EIP55-capitalized ethereum address for this secp256k1 public key
const toAddress = (x, y) => {
    const k256 = web3.utils.soliditySha3(toHex(x, 256), toHex(y, 256))
    return web3.utils.toChecksumAddress(k256.slice(k256.length - 40))
}

describe("SchnorrSECP256K1", async function () {
    // let schnorrSECP256K1;

    // log("SchnorrSECP256K1 address", c);
    const secretKey = hexToBN(
        // Uniformly sampled from {0,...,groupOrder}
        '0x5d18fc9fb6494384932af3bda6fe8102c0fa7a26774e22af3993a69e2ca79565'
    )
    const publicKey = [
        // '>>>' means "computed in python"
        // >>> import py_ecc.secp256k1.secp256k1 as s
        // >>> print("'0x%x',\n'0x%x'" % tuple(s.multiply(s.G, secretKey)))
        '0x6e071bbc2060bce7bae894019d30bdf606bdc8ddc99d5023c4c73185827aeb01',
        '0x9ed10348aa5cb37be35802226259ec776119bbea355597db176c66a0f94aa183'
    ].map(hexToBN)
    const [msgHash, k] = [
        // Arbitrary values to test signature
        '0x18f224412c876d8efb2a3fa670837b5ad1347120363c2b310653f610d382729b',
        '0xd51e13c68bf56155a83e50fd9bc840e2a1847fb9b49cd206a577ecd1cd15e285'
    ].map(hexToBN)
    const kTimesG = [
        // >>> print("'0x%x',\n'0x%x'" % tuple(s.multiply(s.G, k)))
        '0x6c8644d3d376356b540e95f1727b6fd99830d53ef8af963fcc401eeb7b9f8c9f',
        '0xf142b3c0964202b45fb2f862843f75410ce07de04643b28b9ce04633b5fb225c'
    ].map(hexToBN)
    const kTimesGAddress = toAddress(...kTimesG)
    const pubKeyYParity = publicKey[1].isEven() ? 0 : 1
    const e = hexToBN(
        web3.utils.soliditySha3(
            toHex(publicKey[0], 256),
            toHex(pubKeyYParity ? '0x01' : '0x00', 8),
            toHex(msgHash, 256),
            toHex(kTimesGAddress, 160)
        )
    )
    const s = k.sub(e.mul(secretKey)).umod(groupOrder) // s ≡ k - e*secretKey mod groupOrder

    before(async () => {
        const SchnorrSECP256K1 = await ethers.getContractFactory("SchnorrSECP256K1");
        schnorrSECP256K1 = await SchnorrSECP256K1.deploy();
        await schnorrSECP256K1.deployed();
    })

   it('Knows a good Schnorr signature from bad', async () => {
       expect(
            publicKey[0].lt(groupOrder.shrn(1).add(gasUsage))).to.equal(true
            // 'x ordinate of public key must be less than half group order.'
        );

       console.log(
           "\n pubKey", publicKey[0].toString(),
           "\n pubKeyYParity", pubKeyYParity.toString(),
           "\n signature", s.toString(),
           "\n msgHash", msgHash.toString(),
           "\n kTimesGAddress", kTimesGAddress.toLocaleUpperCase()
       )

       const checkSignature = async s =>
           schnorrSECP256K1.verifySignature.call(
               gasUsage,
               publicKey[0].toString(),
               pubKeyYParity.toString(),
               s.toString(),
               msgHash.toString(),
               kTimesGAddress)


       expect(await checkSignature(s)).to.equal(true, 'failed to verify good signature')

       expect(!(await checkSignature(s.add(gasUsage)))).to.equal( true, 'failed to reject bad signature')

       let gasUsed = await schnorrSECP256K1.estimateGas.verifySignature(
            publicKey[0].toString(),
            pubKeyYParity.toString(),
            s.toString(),
            msgHash.toString(),
            kTimesGAddress)
   })

   it('Accepts the OLD MIXED signatures generated on the go side', async () => {
        const tests = require('../../test_data/testsOld')
        const dssTest = require('../../test_data/dssTestOld')
        tests.push(dssTest)
        for (let i = 0; i < Math.min(1, tests.length); i++) {
            const numbers = tests[i].slice(0, tests[i].length - 1)
            const [msgHash, secret, pX, pY, sig] = numbers.map(hexToBN)
            const rEIP55Address = web3.utils.toChecksumAddress(tests[i].pop())
            expect(
                await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.toString(),
                    msgHash.toString(),
                    rEIP55Address
                )).to.equal(true,
                'failed to verify signature constructed by golang tests'
            )
            expect(
                !await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.add(gasUsage).toString(),
                    msgHash.toString(),
                    rEIP55Address
                )).to.equal(true,
                'failed to reject bad signature'
            )
        }
    })

   it('Shuld verify ethdss_test signatutre', async () => {
        const tests = require('../../test_data/ethdss_test')
        for (let i = 0; i < Math.min(1, tests.length); i++) {
            const numbers = tests[i]
            const [pX, pY, sig, msgHash, nonceTimesGeneratorAddress ] = numbers.map(hexToBN)
            let addr = tests[i].pop()
            const rEIP55Address = web3.utils.toChecksumAddress(addr)
            expect(
                await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.toString(),
                    msgHash.toString(),
                    rEIP55Address
                )).to.equal(true,
                'failed to verify signature constructed by golang tests'
            )
            expect(
                !await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.add(gasUsage).toString(),
                    msgHash.toString(),
                    rEIP55Address
                )).to.equal(true,
                'failed to reject bad signature'
            )
        }
    })

    it('Should verify ethschnorr_test signatures', async () => {
        const tests = require('../../test_data/ethschnorr_test')
        for (let i = 0; i < Math.min(1, tests.length); i++) {
            const numbers = tests[i].slice(0, tests[i].length - 1)
            const [pX, pY, sig, msgHash, nonceTimesGeneratorAddress ] = numbers.map(hexToBN)
            let addr = tests[i][tests[i].length-1]
            // log("nonceTimesGeneratorAddress", nonceTimesGeneratorAddress ,"\n",
            //     addr
            // )
            const rEIP55Address = web3.utils.toChecksumAddress(addr)
            expect(
                await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.toString(),
                    msgHash.toString(),
                    rEIP55Address
                )).to.equal(true,
                'failed to verify signature constructed by golang tests'
            )
            expect(
                !await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.add(gasUsage).toString(),
                    msgHash.toString(),
                    rEIP55Address
                )).to.equal(true,
                'failed to reject bad signature'
            )
        }
    })

/*
        pX,
		pY,
		signature.Signature,
		msg,
		signature.CommitmentPublicAddress
* */
    it('Should verify mixed signatures', async () => {
        let testsNew = require('../../test_data/ethschnorr_test')
        let dssTest = require('../../test_data/ethdss_test')
        testsNew.push(dssTest)
        for (let i = 0; i < Math.min(1, testsNew.length); i++) {
            const numbersNew = testsNew[i].slice(0, testsNew[i].length - 1)
            const [pX, pY, sig, msgHash, nonceTimesGeneratorAddress ] = numbersNew.map(hexToBN)
            let addrNew = testsNew[i][testsNew[i].length-1]
            // log("addrNew" , addrNew)
            const rEIP55AddressNew = web3.utils.toChecksumAddress(addrNew)
            // log("rEIP55Address", rEIP55AddressNew)
            expect(
                await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.toString(),
                    msgHash.toString(),
                    rEIP55AddressNew
                )).to.equal(true,
                'failed to verify signature constructed by golang tests')
            expect(
                !await schnorrSECP256K1.verifySignature.call(
                    gasUsage,
                    pX.toString(),
                    pY.isEven() ? 0 : 1,
                    sig.add(gasUsage).toString(),
                    msgHash.toString(),
                    rEIP55AddressNew
                )).to.equal(true,
                'failed to reject bad signature')
        }
    })
})



// async function checkSignature (s) =>  {
//  return   schnorrSECP256K1.verifySignature.call(
//         gasUsage,
//         publicKey[0].toString(),
//         pubKeyYParity.toString(),
//         s.toString(),
//         msgHash.toString(),
//         kTimesGAddress)
// }
