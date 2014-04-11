// Copyright (coffee) 2014, proactiveRISK INC. - http://www.proactiverisk.com
//
// This file is part of Heartbleed Tool OpenSSL CVE-2014-0160
//
// Heartbleed-Ext Tool is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// Heartbleed-Ext is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// Heartbleed Tool.  If not, see <http://www.gnu.org/licenses/>.

var EXPORTED_SYMBOLS=["HeartbleedCheckerBackgound"];

//background page code
var HeartbleedCheckerBackgound={
		//store the sites and vulnerability status (this list grows as pages are browsed)
	sites:['amazonaws.com','google.com','facebook.com','etsy.com','thinkgeek.com','github.com','yahoo.com','twitter.com','pinterest.com'],
	results:[1,1,1,1,1,1,1,1,1],
	messages:["","","","","","","","",""],
	enabled:true
};


