/* -----------------------------------------------------
  OTP testing code
  ----------------------------------------------------- */

let jsc = new JsConfig({ autoSave: true, version: 1, capitalize: true })
  .add("type", JsConfig.listType("totp", "hotp"), "totp", "OTP type", "")
  .add("secret", JsConfig.textType(".*"), "0123456789ABCDEF1234", "Secret Key", "")
  .add("issuer", JsConfig.textType(" *[^ ]* *"), "ACME", "Issuer name", "")
  .add("name", JsConfig.textType(" *[^ ]* *"), "johndoe", "User name", "")
  .add("algo", JsConfig.listType("SHA1", "SHA256", "SHA512"), "SHA1", "Digest algorithm", "")
  .add("digits", JsConfig.listType("6", "8", "10"), "6", "Number of OTP digits", "")
  .add("period", JsConfig.listType("5", "15", "30", "60", "120"), "30", "Validity period in second", "t")
  .add("counter", JsConfig.numType(0, 99999, 1), 0, "Event counter", "h")
  .add("first-OTP", JsConfig.textType("[0-9]*"), "", "First OTP to look for", "")
  .add("next-OTP", JsConfig.textType("[0-9]*"), "", "Next OTP expected", "")
  .add("drift", JsConfig.numType(0, 99999, 1), 0, "Clock drift in number of periods", "t")
  .add("OTP", JsConfig.textType("[0-9]*"), "", "OTP to verify", "")
  .add("search-periods", JsConfig.listType("10", "100", "1000", "10000"), "10", "Number of periods to look in", "")
  .add("window", JsConfig.numType(0, 40, 1), 2, "Number of OTPs to verify before and after the current one", "");
let config = jsc._,
  timer,
  base32padding = true;

function configChanged() {
  let params;
  if (config.type == "hotp") {
    $(".t").hide();
    $(".h").show();
    params = "counter=" + config.counter;
    updateDrift(0, true);
  } else {
    $(".h").hide();
    $(".t").show();
    params = "period=" + config.period;
  }

  let url = "otpauth://" + config.type
    + "/" + encodeURIComponent(config.issuer)
    + ":" + encodeURIComponent(config.name)
    + "?secret=" + base32Encode(getSecret(), base32padding)
    + "&issuer=" + encodeURIComponent(config.issuer)
    + "&algorithm=" + config.algo
    + "&digits=" + config.digits
    + "&" + params;

  $("#qrcode")[0].innerHTML = "";
  var qrcode = new QRCode("qrcode", {
    text: url,
    width: 200,
    height: 200,
    colorDark: "#000000",
    colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.H,
  });

  showOTP();
}

jsc.onChange(configChanged).showConfigTable($("#config")[0], false);
$("#jsconfig-row-window").detach().appendTo("#otps-config");
$("#jsconfig-row-issuer").detach().appendTo("#qrcode-config");
$("#jsconfig-row-name").detach().appendTo("#qrcode-config");
$("#jsconfig-row-first-OTP").detach().appendTo("#resync-config");
$("#jsconfig-row-next-OTP").detach().appendTo("#resync-config");
$("#jsconfig-row-drift").detach().appendTo("#verif-config");
$("#jsconfig-row-OTP").detach().appendTo("#verif-config");
$("#jsconfig-row-search-periods").detach().appendTo("#resync-config");

// -----------------------------------------
// OTP utils
// -----------------------------------------

function getOTPCounter() {
  return config.drift +
    (config.type == "hotp" ?
      config.counter
      : Math.floor(Date.now() / (config.period * 1000))
    );
}

let validOTPs;
async function showOTP() {

  function addOTP(otp) {
    validOTPs.push(otp);
    const re = new RegExp("(\\d{" + config.digits / 2 + "})", "g");
    return `<div>${otp.replace(re, "$1&nbsp;").replace(/(&nbsp;$)/, "")}</div>`;
  }

  function updateTimeLeft() {
    const timeLeft = (counter - config.drift + 1) * config.period * 1000 - Date.now();
    const pctLeft = Math.round((timeLeft / 1000 / config.period) * 100);
    $(".countdown").css("width", pctLeft + "%");
    return timeLeft;
  }

  const counter = getOTPCounter();
  let otp = await generateHOTP(
    getSecret(),
    config.algo,
    config.digits,
    counter
  );
  validOTPs = [];
  $("#current")[0].innerHTML = addOTP(otp);
  $("#previous")[0].innerHTML = "";
  $("#next")[0].innerHTML = "";
  for (let w = 1; w <= config.window; w++) {
    if (counter - w >= 0) {
      otp = await generateHOTP(
        getSecret(),
        config.algo,
        config.digits,
        counter - w
      );
      $("#previous")[0].innerHTML += addOTP(otp);
    }
    otp = await generateHOTP(
      getSecret(),
      config.algo,
      config.digits,
      counter + w
    );
    $("#next")[0].innerHTML += addOTP(otp);
  }

  updateTimeLeft();
  verifyOTP();

  if (timer) {
    clearTimeout(timer);
    timer = undefined;
  }

  if (config.type == "totp") {
    timer = setInterval(() => {
      const timeLeft = updateTimeLeft();
      if (timeLeft < 0) {
        $(".countdown").css("width", "100%");
        return showOTP();
      }
      updateTimeLeft();
    }, 1000);
  }
}

// -----------------------------------------
// OTP validation
// -----------------------------------------

function parseOtp(otp) {
  return otp ? otp.replaceAll(" ", "") : otp;
}
function verifyOTP() {
  const otp = parseOtp($("#OTP").val());
  if (otp) {
    $("#OTP").attr("class", validOTPs.includes(otp) ? "valid" : "invalid");
  } else {
    $("#OTP").removeAttr("class");
  }
}

$("#OTP").on("keyup", verifyOTP);

function updateDrift(newDrift, noShow) {
  config.drift = newDrift;
  $("#drift").val(config.drift);
  if (!noShow) {
    showOTP();
  }
}

function updateCounter(newCounter) {
  config.counter = newCounter;
  $("#counter").val(config.counter);
  showOTP();
}

// -----------------------------------------
// Secret generation
// -----------------------------------------

const secretLabel = $($("td[title='Secret Key']")[0]);

secretLabel.addClass("action");
secretLabel.on("click", async () => {
  let secret = new Uint32Array(20);
  crypto.getRandomValues(secret);
  config.secret = bytesToHex(secret);
  $("#secret").val(config.secret);
  configChanged();
});

function getSecret() {
  return hexToBytes(config.secret);
}

// -----------------------------------------
// Resynchronize
// -----------------------------------------
$("#resync").on("click", async () => {
  $("#resync").prop("disabled", true);
  function resyncStatus(msg) {
    $("#resync-status").text(msg);
    setTimeout(() => {
      $("#resync-status").text("");
    }, 2000);
  }
  const resyncWin = Number.parseInt(config["search-periods"]);
  const resyncOTPs = [
    parseOtp(config["first-OTP"]),
    parseOtp(config["next-OTP"])
  ],
    counter = getOTPCounter(),
    from = Math.max(0, counter - resyncWin),
    to = counter + resyncWin;
  let resyncState = 0;

  for (let c = from; c <= to; c++) {
    let otp = await generateHOTP(
      getSecret(),
      config.algo,
      config.digits,
      c
    );
    if (otp == resyncOTPs[resyncState]) {
      if (resyncState == 1) {
        resyncState++;
        // found 2 consecutive!
        if (config.type == "hotp") {
          updateCounter(c + 1);
          // added 1 for hotp because 2nd otp has been consumed
        } else {
          updateDrift(c - counter + config.drift);
        }
        break;
      } else {
        // found 1
        resyncState++;
      }
    } else {
      resyncState = 0;
    }
  }
  resyncStatus(resyncState == 2 ? "Resynchronized!" : "OTPs not found.");
  $("#resync").prop("disabled", false);
});

// Go!

configChanged();
