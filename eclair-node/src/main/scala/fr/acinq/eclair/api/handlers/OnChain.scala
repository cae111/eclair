/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.api.handlers

import akka.http.scaladsl.server.Route
import fr.acinq.bitcoin.psbt.Psbt
import fr.acinq.bitcoin.scalacompat.{DeterministicWallet, Satoshi}
import fr.acinq.eclair.api.Service
import fr.acinq.eclair.api.directives.EclairDirectives
import fr.acinq.eclair.api.serde.FormParamExtractors._
import org.json4s.{JArray, JBool, JObject, JString}

import java.util.Base64

trait OnChain {
  this: Service with EclairDirectives =>

  import fr.acinq.eclair.api.serde.JsonSupport.{formats, marshaller, serialization}

  val getNewAddress: Route = postRequest("getnewaddress") { implicit t =>
    complete(eclairApi.newAddress())
  }

  val sendOnChain: Route = postRequest("sendonchain") { implicit t =>
    formFields("address".as[String], "amountSatoshis".as[Satoshi], "confirmationTarget".as[Long]) {
      (address, amount, confirmationTarget) =>
        complete(eclairApi.sendOnChain(address, amount, confirmationTarget))
    }
  }

  val onChainBalance: Route = postRequest("onchainbalance") { implicit t =>
    complete(eclairApi.onChainBalance())
  }

  val onChainTransactions: Route = postRequest("onchaintransactions") { implicit t =>
    withPaginated { paginated_opt =>
      formFields(countFormParam, skipFormParam) { (count_opt, skip_opt) =>
        val count = paginated_opt.map(_.count).getOrElse(10)
        val skip = paginated_opt.map(_.skip).getOrElse(0)
        complete(eclairApi.onChainTransactions(count, skip))
      }
    }
  }

  val globalBalance: Route = postRequest("globalbalance") { implicit t =>
    complete(eclairApi.globalBalance())
  }

  val enumerate: Route = postRequest("enumerate") { implicit t =>
    val master = this.eclairApi.getOnchainMasterPubKey
    val json = new JObject(List(
      "type" -> JString("eclair"),
      "model" -> JString("eclair"),
      "label" -> JString(""),
      "path" -> JString(""),
      "fingerprint" -> JString((DeterministicWallet.fingerprint(master) & 0xFFFFFFFFL).toHexString),
      "needs_pin_sent" -> JBool(false),
      "needs_passphrase_sent" -> JBool(false)
    ))
    complete(List(json))
  }

  val getmasterxpub: Route = postRequest("getmasterxpub") { implicit t =>
    val xpub = DeterministicWallet.encode(this.eclairApi.getOnchainMasterPubKey, DeterministicWallet.xpub)
    complete(new JObject(List("xpub" -> JString(xpub))))
  }

  val getdescriptors: Route = postRequest("getdescriptors") { implicit t =>
    formFields("fingerprint".as[String], "chain".as[String].?, "account".as[Long]) {
      (fingerprint, chain_opt, account) =>
        val (receiveDescs, internalDescs) = this.eclairApi.getDescriptors(Integer.parseUnsignedInt(fingerprint, 16), chain_opt, account)
        val json = new JObject(List(
          "receive" -> JArray(receiveDescs.map(s => JString(s))),
          "internal" -> JArray(internalDescs.map(s => JString(s)))
        ))
        complete(json)
    }
  }

  val signtx: Route = postRequest("signtx") { implicit t =>
    formFields("psbt".as[String], "fingerprint".as[String], "chain".as[String].?) { (base64, fingerprint, chain_opt) =>
      val psbt = Psbt.read(Base64.getDecoder.decode(base64)).getRight
      logger.info { s"signing $psbt" }
      val psbt1 = this.eclairApi.signPsbt(psbt, Integer.parseUnsignedInt(fingerprint, 16), chain_opt)
      val json = new JObject(List("psbt" -> JString(Base64.getEncoder.encodeToString(Psbt.write(psbt1).toByteArray))))
      complete(json)
    }
  }

  val onChainRoutes: Route = getNewAddress ~ sendOnChain ~ onChainBalance ~ onChainTransactions ~ globalBalance ~ enumerate ~ getmasterxpub ~ getdescriptors ~ signtx

}
