package fr.acinq.eclair.integration

import akka.actor.ActorSystem
import akka.pattern.pipe
import akka.testkit.TestProbe
import com.typesafe.config.ConfigFactory
import fr.acinq.bitcoin.psbt.Psbt
import fr.acinq.bitcoin.scalacompat.{Block, ByteVector32, Satoshi, Script, Transaction, TxOut}
import fr.acinq.eclair.blockchain.OnChainWallet.FundTransactionResponse
import fr.acinq.eclair.blockchain.bitcoind.BitcoindService.BitcoinReq
import fr.acinq.eclair.blockchain.bitcoind.rpc.BitcoinCoreClient.ProcessPsbtResponse
import fr.acinq.eclair.blockchain.bitcoind.rpc.{BasicBitcoinJsonRPCClient, BitcoinCoreClient}
import fr.acinq.eclair.blockchain.fee.{FeeratePerByte, FeeratePerKw}
import fr.acinq.eclair.{Boot, Setup, addressToPublicKeyScript}
import org.json4s.{JInt, JObject, JString}

import java.io.File
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import scala.jdk.CollectionConverters.MapHasAsJava

class HwiIntegrationSpec extends IntegrationSpec {
  test("create wallet") {
    import fr.acinq.bitcoin.scalacompat.KotlinUtils._

    val config = ConfigFactory.parseMap(Map("eclair.api.enabled"-> true, "eclair.api.password" -> "foobar", "eclair.api.port" -> 8080).asJava)
      .withFallback(withDefaultCommitment)
      .withFallback(commonConfig)
    val name = "eclair"
    val datadir = new File(INTEGRATION_TMP_DIR, s"datadir-eclair-$name")
    datadir.mkdirs()
    implicit val system: ActorSystem = ActorSystem(s"system-$name", config)
    val setup = new Setup(datadir, pluginParams = Seq.empty)
    val kit = Await.result(setup.bootstrap, 10 seconds)

    Boot.startApiServiceIfEnabled(kit)
    val sender = TestProbe()
    sender.send(bitcoincli, BitcoinReq("getblockcount"))
    sender.expectMsgType[JInt]

    bitcoinrpcclient.invoke("createwallet", "eclair", true, false, "", false, true, true, true).pipeTo(sender.ref)
    assert(JString("eclair") == sender.expectMsgType[JObject] \ "name")

    val defaultWallet = new BitcoinCoreClient(bitcoinrpcclient)
    val eclairWallet = new BitcoinCoreClient(new BasicBitcoinJsonRPCClient(rpcAuthMethod = bitcoinrpcauthmethod, host = "localhost", port = bitcoindRpcPort, wallet = Some("eclair")))
    eclairWallet.getReceiveAddress().pipeTo(sender.ref)
    val address = sender.expectMsgType[String]
    defaultWallet.sendToAddress(address, Satoshi(10000000L), 1).pipeTo(sender.ref)
    sender.expectMsgType[ByteVector32]
    generateBlocks(3)
    val tx = Transaction(version = 2, txIn = Nil, txOut = TxOut(Satoshi(100000), Script.write(addressToPublicKeyScript(address, Block.RegtestGenesisBlock.hash))) :: Nil, lockTime = 0)
    eclairWallet.fundTransaction(tx, FeeratePerKw(FeeratePerByte(Satoshi(5))), true).pipeTo(sender.ref)

    val fundedTx = sender.expectMsgType[FundTransactionResponse].tx
    val unsignedPsbt = new Psbt(fundedTx)
    eclairWallet.signPsbt(unsignedPsbt).pipeTo(sender.ref)
    val ProcessPsbtResponse(psbt, complete) = sender.expectMsgType[ProcessPsbtResponse]
    assert(complete)
  }
}
