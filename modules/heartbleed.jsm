var EXPORTED_SYMBOLS=["HeartbleedCheckerBackgound"];

//background page code
var HeartbleedCheckerBackgound={
		//store the sites and vulnerability status (this list grows as pages are browsed)
	sites:['amazonaws.com','google.com','facebook.com','etsy.com','thinkgeek.com','github.com','yahoo.com','twitter.com','pinterest.com'],
	results:[1,1,1,1,1,1,1,1,1],
	messages:["","","","","","","","",""],
	enabled:true
};


