/* -----------------------------------------------------
  OTP testing code
  ----------------------------------------------------- */

let jsc = new JsConfig({ autoSave: true, version: 1 })
  .add("type", JsConfig.listType("totp", "hotp"), "totp", "OTP type", "")
  .add("secret", JsConfig.textType(".*"), "12345678901234567890", "Secret Key", "")
  .add("base32", JsConfig.boolType(), false, "Check if secret is base32 encoded", "")
  .add("issuer", JsConfig.textType(" *[^ ]* *"), "ACME", "Issuer name", "")
  .add("name", JsConfig.textType(" *[^ ]* *"), "johndoe", "User name", "")
  .add("algo", JsConfig.listType("SHA1", "SHA256", "SHA512"), "SHA1", "Digest algorithm", "")
  .add("digits", JsConfig.listType("6", "8", "10"), "6", "Number of OTP digits", "")
  .add("period", JsConfig.listType("10", "30", "60"), "30", "Validity period in second", "t")
  .add("counter", JsConfig.numType(0, 99999, 1), 0, "Event counter", "h")
  .add("window", JsConfig.numType(0, 40, 1), 2, "Number of OTPs to verify before and after the current one", "");
let config = jsc._,
  timer,
  drift = 0,
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
    + "?secret=" + (config.base32 ? config.secret : base32Encode(config.secret, base32padding))
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

// -----------------------------------------
// OTP utils
// -----------------------------------------

function getOTPCounter() {
  return drift +
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
    const timeLeft = (counter - drift + 1) * config.period * 1000 - Date.now();
    const pctLeft = Math.round((timeLeft / 1000 / config.period) * 100);
    $(".countdown").css("width", pctLeft + "%");
    return timeLeft;
  }

  const counter = getOTPCounter();
  let otp = await generateHOTP(
    config.secret,
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
        config.secret,
        config.algo,
        config.digits,
        counter - w
      );
      $("#previous")[0].innerHTML += addOTP(otp);
    }
    otp = await generateHOTP(
      config.secret,
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

function readOtp(id) {
  return $(id).val().replaceAll(" ", "");
}
function verifyOTP() {
  const otp = readOtp("#otp-in");
  if (otp) {
    $("#otp-in").attr("class", validOTPs.includes(otp) ? "valid" : "invalid");
  } else {
    $("#otp-in").removeAttr("class");
  }
}

$("#otp-in").on("keyup", verifyOTP);
function updateDrift(newDrift, noShow) {
  drift = newDrift;
  $("#drift").val(drift);
  if (!noShow) {
    showOTP();
  }
}
function updateCounter(newCounter) {
  config.counter = newCounter;
  $("#counter").text(config.counter);
  showOTP();
}

// -----------------------------------------
// Drift setting
// -----------------------------------------

$("#drift").on("change", async () => {
  let newDrift = $("#drift").val().trim();
  if (!newDrift || isNaN(newDrift)) {
    newDrift = drift;
  }
  try {
    updateDrift(Number.parseInt(newDrift));
  } catch (err) {
    console.error("Invalid value", err);
  }
});

$("#drift").on("contextmenu", async (event) => {
  event.preventDefault();
  $("#otp-sync1, #otp-sync2").val("");
  updateDrift(0);
  return false;
});

// -----------------------------------------
// Secret generation
// -----------------------------------------

const secretLabel = $($("td[title='Secret Key']")[0]);

secretLabel.addClass("action");
secretLabel.on("click", async () => {
  // Printable ASCII 33 to 125
  const min = 33, max = 125;
  let secret = "";
  for (let i = 0; i < 20; i++) {
    secret += String.fromCharCode(min + Math.floor(Math.random() * (max - min)));
  }
  config.secret = secret;
  $("#secret").val(secret);
  config.base32 = false;
  $("#base32").prop("checked", false);
  configChanged();
});

// -----------------------------------------
// Resynchronize
// -----------------------------------------
$("#resync").on("click", async () => {
  function resyncStatus(msg) {
    $("#resync-status").text(msg);
    setTimeout(() => {
      $("#resync-status").text("");
    }, 2000);
  }
  const resyncWin = $("#resync-window").val();
  const resyncOTPs = [
    readOtp("#otp-sync1"),
    readOtp("#otp-sync2")
  ],
    counter = getOTPCounter(),
    from = Math.max(0, counter - resyncWin),
    to = counter + resyncWin;
  let resyncState = 0;

  for (let c = from; c <= to; c++) {
    let otp = await generateHOTP(
      config.secret,
      config.algo,
      config.digits,
      c
    );
    if (otp == resyncOTPs[resyncState]) {
      if (resyncState == 1) {
        // found 2 consecutive!
        if (config.type == "hotp") {
          updateCounter(c + 1);
        } else {
          updateDrift(c - counter + drift);
        }
        // added 1 for hotp because 2nd otp has been consumed
        resyncStatus("Resynchronized done!");
        return;
      } else {
        // found 1
        resyncState++;
      }
    } else {
      resyncState = 0;
    }
  }
  resyncStatus("OTPs not found.");
});

// Go!

configChanged();
