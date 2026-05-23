#!/usr/bin/env node

import axios, { AxiosResponse } from "axios";
import cliProgress from "cli-progress";
import crypto from "crypto";
import fs from "fs";
import { XMLParser } from "fast-xml-parser";
import path from "path";
import unzip from "unzip-stream";
import yargs from "yargs";

import { handleAuthRotation } from "./utils/authUtils";
import {
  getBinaryInformMsg,
  getBinaryInitMsg,
  getDecryptionKey,
} from "./utils/msgUtils";
import { version as packageVersion } from "./package.json";

// There is no viable option other than using the `unzip-stream` module, however,
// it depends on an extremely old dependency `binary`, which uses `new Buffer()`
// and causes node to complain. Suppress warnings until we find an alternative.
process.removeAllListeners("warning");

const parser = new XMLParser({});

const getLatestVersion = async (
  region: string,
  model: string
): Promise<{ pda: string; csc: string; modem: string }> => {
  return axios
    .get(
      `https://fota-cloud-dn.ospserver.net/firmware/${region}/${model}/version.xml`
    )
    .then((res: AxiosResponse) => {
      const [pda, csc, modem] = parser
        .parse(res.data)
        .versioninfo.firmware.version.latest.split("/");

      return { pda, csc, modem };
    });
};

const main = async (region: string, model: string, imei: string): Promise<void> => {
  console.log(`
  Model: ${model}
  Region: ${region}`);

  const { pda, csc, modem } = await getLatestVersion(region, model);

  console.log(`
  Latest version:
    PDA: ${pda}
    CSC: ${csc}
    MODEM: ${modem !== "" ? modem : "N/A"}`);

  const nonce = {
    encrypted: "",
    decrypted: "",
  };

  const cookiesMap = new Map<string, string>(); // Add session cookie jar

  const headers: Record<string, string> = {
    "User-Agent": "Kies2.0_FUS",
    "X-FUS-Protocol-Ver": "2.0",
  };

  const handleHeaders = (responseHeaders: any) => {
    if (responseHeaders.nonce != null) {
      const { Authorization, nonce: newNonce } =
      handleAuthRotation(responseHeaders);

      Object.assign(nonce, newNonce);
      headers.Authorization = Authorization;
    }

    // Persist ALL cookies (JSESSIONID + Akamai/WAF bot cookies)
    if (responseHeaders["set-cookie"]) {
      responseHeaders["set-cookie"].forEach((cookieStr: string) => {
        const cookie = cookieStr.split(";")[0];
        const [key, ...val] = cookie.split("=");
        cookiesMap.set(key, val.join("="));
      });

      headers.Cookie = Array.from(cookiesMap.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
    }
  };
  await axios
    .post("https://neofussvr.sslcs.cdngc.net/NF_DownloadGenerateNonce.do", "", {
      headers: {
        Authorization:
          'FUS nonce="", signature="", nc="", type="", realm="", newauth="1"',
        "User-Agent": "Kies2.0_FUS",
        "X-FUS-Protocol-Ver": "2.0",
        Accept: "application/xml",
      },
    })
    .then((res) => {
      handleHeaders(res.headers);
      return res;
    });

  const {
    binaryByteSize,
    binaryDescription,
    binaryFilename,
    binaryLogicValue,
    binaryModelPath,
    binaryOSVersion,
    binaryVersion,
  } = await axios
    .post(
      "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInform.do",
      getBinaryInformMsg(
        `${pda}/${csc}/${modem !== "" ? modem : pda}/${pda}`,
        region,
        model,
        nonce.decrypted,
        imei
      ),
      {
        headers: {
          ...headers,
          Accept: "application/xml",
          "Content-Type": "application/xml",
        },
      }
    )
    .then((res) => {
      handleHeaders(res.headers);
      return res;
    })
    .then((res: AxiosResponse) => {
      const parsedInfo = parser.parse(res.data);

      return {
        binaryByteSize: parsedInfo.FUSMsg.FUSBody.Put.BINARY_BYTE_SIZE.Data,
        binaryDescription: parsedInfo.FUSMsg.FUSBody.Put.DESCRIPTION.Data,
        binaryFilename: parsedInfo.FUSMsg.FUSBody.Put.BINARY_NAME.Data,
        binaryLogicValue:
          parsedInfo.FUSMsg.FUSBody.Put.LOGIC_VALUE_FACTORY.Data,
        binaryModelPath: parsedInfo.FUSMsg.FUSBody.Put.MODEL_PATH.Data,
        binaryOSVersion: parsedInfo.FUSMsg.FUSBody.Put.CURRENT_OS_VERSION.Data,
        binaryVersion: parsedInfo.FUSMsg.FUSBody.Results.LATEST_FW_VERSION.Data,
      };
    });

  console.log(`
  OS: ${binaryOSVersion}
  Filename: ${binaryFilename}
  Size: ${binaryByteSize} bytes
  Logic Value: ${binaryLogicValue}
  Description:
    ${binaryDescription.split("\n").join("\n    ")}`);

  const decryptionKey = getDecryptionKey(binaryVersion, binaryLogicValue);

  await axios
    .post(
      "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInitForMass.do",
      getBinaryInitMsg(binaryFilename, nonce.decrypted),
      {
        headers: {
          ...headers,
          Accept: "application/xml",
          "Content-Type": "application/xml",
        },
      }
    )
    .then((res) => {
      handleHeaders(res.headers);
      return res;
    });

  const binaryDecipher = crypto.createDecipheriv(
    "aes-128-ecb",
    decryptionKey,
    null
  );

  await axios
  .get(
    `http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file=${binaryModelPath}${binaryFilename}`,
    {
      headers: {
        ...headers,
        // Manually inject the encrypted nonce ONLY for the final download stream
        Authorization: headers.Authorization.replace('nonce=""', `nonce="${nonce.encrypted}"`),
      },
      responseType: "stream",
    }
  )
    .then((res: AxiosResponse) => {
      const outputFolder = `${process.cwd()}/${model}_${region}/`;
      console.log();
      console.log(outputFolder);
      fs.mkdirSync(outputFolder, { recursive: true });

      let downloadedSize = 0;
      let currentFile = "";
      const progressBar = new cliProgress.SingleBar({
        format: "{bar} {percentage}% | {value}/{total} | {file}",
        barCompleteChar: "\u2588",
        barIncompleteChar: "\u2591",
      });
      progressBar.start(binaryByteSize, downloadedSize);

      return res.data
        .on("data", (buffer: Buffer) => {
          downloadedSize += buffer.length;
          progressBar.update(downloadedSize, { file: currentFile });
        })
        .pipe(binaryDecipher)
        .pipe(unzip.Parse())
        .on("entry", (entry) => {
          currentFile = `${entry.path.slice(0, 18)}...`;
          progressBar.update(downloadedSize, { file: currentFile });
          entry
            .pipe(fs.createWriteStream(path.join(outputFolder, entry.path)))
            .on("finish", () => {
              if (downloadedSize === binaryByteSize) {
                console.log();
                process.exit();
              }
            });
        });
    });
};

const { argv } = yargs
  .option("model", {
    alias: "m",
    describe: "Model",
    type: "string",
    demandOption: true,
  })
  .option("region", {
    alias: "r",
    describe: "Region",
    type: "string",
    demandOption: true,
  })
  .option("imei", {
    alias: "i",
    describe: "IMEI",
    type: "string",
    demandOption: true,
  })
  .version(packageVersion)
  .alias("v", "version")
  .help();

main(argv.region, argv.model, argv.imei);

export {};
