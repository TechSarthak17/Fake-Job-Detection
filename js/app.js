document.getElementById("jobForm").addEventListener("submit", function(e){

e.preventDefault();

let email = document.getElementById("email").value.toLowerCase();
let message = document.getElementById("message").value.toLowerCase();

let risk = 0;
let reasons = [];


/* EMAIL CHECK */

if(
email.includes("@gmail.com") ||
email.includes("@yahoo.com") ||
email.includes("@outlook.com")
){
risk += 20;
reasons.push("Free email domain used");
}


/* SCAM KEYWORD VARIATIONS */

let scamKeywords = [

"registration fee",
"registration charges",

"training fee",
"training charges",

"processing fee",
"processing charges",

"security deposit",

"documentation fee",
"documentation charges",

"onboarding fee",
"onboarding charges",

"guaranteed job",
"urgent hiring"

];

scamKeywords.forEach(keyword => {

if(message.includes(keyword)){

risk += 25;
reasons.push("Scam keyword detected: " + keyword);

}

});


/* PAYMENT REQUEST DETECTION */

let paymentWords = [

"pay",
"payment",
"transfer",
"upi",
"rs",
"₹",
"rupees",
"deposit"

];

paymentWords.forEach(word => {

if(message.includes(word)){

risk += 15;
reasons.push("Possible payment request detected");

}

});


/* RISK LIMIT */

risk = Math.min(risk, 100);


/* EMPTY RESULT FIX */

if(reasons.length === 0){

reasons.push("No major scam indicators detected");

}


/* RISK LEVEL */

let riskLevel = "";
let color = "";

if(risk <= 30){

riskLevel = "SAFE";
color = "green";

}

else if(risk <= 60){

riskLevel = "SUSPICIOUS";
color = "orange";

}

else{

riskLevel = "HIGH RISK";
color = "red";

}


/* FINAL RESULT */

let result = document.getElementById("result");

result.innerHTML = `

<h3>Risk Score: ${risk}</h3>

<h2 style="color:${color};">${riskLevel}</h2>

<p>${reasons.join("<br>")}</p>

`;

});