// Copyright (coffee) 2014, proactiveRISK INC. - http://www.proactiverisk.com
//
// This file is part of Heartbleed-Ext Tool OpenSSL CVE-2014-0160
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

Components.utils.import("resource://heartbleed/heartbleed.jsm");

var HeartbleedChecker={
		prefService:null,
		heartbleedButton:null,
		panel:null,
		hrefPrev:null,
		bundle:null,

		//intitialize HeartbleedChecker
		init:function() {
			//remove the window onload as it is not needed anymore
			window.removeEventListener("load",HeartbleedChecker.init,false);

			//get the string-bundle
			HeartbleedChecker.bundle=document.getElementById("heartbleed-string-bundle");

//			//load preferences
//			HeartbleedChecker.loadPreferences();


			//add page load listener to check new pages for anchors
			gBrowser.addEventListener("DOMContentLoaded",HeartbleedChecker.pageLoaded,false);

			//set the preference service
			HeartbleedChecker.prefService=Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefBranch);

			//check if this is the first install and if so, then store that it was installed
			let prefInstallComplete="heartbleed.checker.install.complete";

			//if the button has not been installed before, then install it
			if(!HeartbleedChecker.prefService.prefHasUserValue(prefInstallComplete)) {
				let toolbar=document.getElementById("nav-bar");
				let buttonId="heartbleed-button";
				
            	//downloads button not found so try putting it after the search container
            	let before=document.getElementById("search-container");
            	if(before) {
	            	//put it before the element after the search container
	            	before=before.nextElementSibling;
            	} else {
            		//if the search container was not found, put before the last element of the toolbar
            		before=toolbar.lastChild;
            	};
	            
				//add the button, and make it persist between runs
				toolbar.insertItem(buttonId,before);
				toolbar.setAttribute("currentset",toolbar.currentSet);
				document.persist(toolbar.id,"currentset");
			 
				//if the navigation toolbar is hidden, show it, so the user can see the button
				toolbar.collapsed=false;

				//store that we have installed the button at least once
				HeartbleedChecker.prefService.setBoolPref(prefInstallComplete,true);
			}
			//store the toolbar button reference for later use
			HeartbleedChecker.heartbleedButton=document.getElementById("heartbleed-button");
		},

		//shutdown HeartbleedChecker
		destroy:function() {
			//remove the page load and tab selected listeners
			gBrowser.removeEventListener("DOMContentLoaded",HeartbleedChecker.pageLoaded,false);
		},
		
		//show the informational popup
		showPopup:function() {
			console.log("showPopup()");
			//set status of enable button
			document.getElementById("chkEnabled").checked=HeartbleedCheckerBackgound.enabled;
			//open the popup panel
			HeartbleedChecker.panel=document.getElementById("heartbleed-panel");
			HeartbleedChecker.panel.openPopup(HeartbleedChecker.heartbleedButton,"after_end",0,0,false,false);
		},
		
		//page was loaded so check the host
		pageLoaded:function(event) {
			//check if enabled first
			if(!HeartbleedCheckerBackgound.enabled) return;
			
			let index;
			let host=window.content.document.location.host;
			
	        let doc = event.originalTarget; // doc is document that triggered the event
	        let win = doc.defaultView; // win is the window for the doc
	        //only trigger once for the top page
	        if(doc.nodeName!="#document") return; // only documents
	        if(win!=win.top) return; //only top window.
	        if(win.frameElement) return; // skip iframes/frames

			console.log("pageLoaded host:"+host+"  nodeName:"+event.originalTarget.nodeName);
			//check to see if host was already checked
			index=HeartbleedCheckerBackgound.sites.indexOf(host);
			if(index==-1) {
				//not checked yet so 
				if(host.length) {
					console.log("checking host:"+host);
					HeartbleedChecker.checkHost(host,function(result,message) {
						//add this host to the checked list so it is not checked again
						HeartbleedCheckerBackgound.sites.push(host);
						HeartbleedCheckerBackgound.results.push(result);
						HeartbleedCheckerBackgound.messages.push(message);
						HeartbleedChecker.updateStatus(host,result,message);
					});
				}
			} else {
				//used cached result
				result=HeartbleedCheckerBackgound.results[index];
				message=HeartbleedCheckerBackgound.messages[index];
				HeartbleedChecker.updateStatus(host,result,message);
			}
		},
		
		//check this domain to see if it is vulnerable
		checkHost:function(host,callback) {
			let url="http://bleed-1161785939.us-east-1.elb.amazonaws.com/bleed/"+host;
			let req=new XMLHttpRequest();
			let json;

			req.onreadystatechange=function(e) {
				if(req.readyState==4) {
					if(req.status==200) {
						//a result was returned
						console.log(req.responseText);
						try{
							json=JSON.parse(req.responseText);
//						    uncomment these to force showing different errors
//							json={"code":0,"data":"([]uint8) {\n 00000000  02 00 79 68 65 61 72 74  62 6c 65 65 64 2e 66 69  |..yheartbleed.fi|\n 00000010  6c 69 70 70 6f 2e 69 6f  59 45 4c 4c 4f 57 20 53  |lippo.ioYELLOW S|\n 00000020  55 42 4d 41 52 49 4e 45  9a 06 9d ff f9 0f 56 40  |UBMARINE......V@|\n 00000030  e7 57 e3 48 95 11 d3 fe  78 02 3f f4 52 b6 14 03  |.W.H....x.?.R...|\n 00000040  03 00 01 01 00 00 00 00  00 0a 00 08 00 06 00 17  |................|\n 00000050  00 18 00 19 00 0b 00 02  01 00 00 0d 00 0a 00 08  |................|\n 00000060  04 01 04 03 02 01 02 03  ff 01 00 01 00 c0 0c c0  |................|\n 00000070  02 00 05 00 04 00 15 00  12 00 09 00 04 70 52 88  |.............pR.|\n 00000080  b8 c9 c6 14 a0 27 38 2f  13 da 4e 42              |.....\"8/..NB|\n}\n","error":"","host":"zeobit.com"};
//							json={"code":2,"error":"This is a test caution error"};
//							json={"code":-1,"error":"This is a test response error"};
						} catch(error) {
							json={"code":-1,"error":error.message};
						}
						if(callback) callback(json.code,json.error);
					} else {
						//there was an error calling the site
						console.log(req.responseText);
						if(callback) callback(-1,req.responseText);
					}
				}
			}
			
			req.open("GET",url,true);
			req.setRequestHeader("Accept","application/json");
			req.send(null);
		},
		
		updateStatus:function(host,result,message) {
			let nb=gBrowser.getNotificationBox();
			let label;
			switch(result) {
				case -1:
					//request failed, so unknown whether this site is vulnerable
					console.log("request failed:"+message);
//					label=HeartbleedChecker.bundle.getString("heartbleed.warning.label")+" "+message;
//					nb.appendNotification(label,"heartbleed.notification","chrome://heartbleed/skin/heartbleed_32_yellow.png",nb.PRIORITY_WARNING_LOW);
					HeartbleedChecker.heartbleedButton.setAttribute("class","yellow");
					break;
				case 0:
					//site is vulnerable so show notification
					console.log("site is vulnerable!");
					label=HeartbleedChecker.bundle.getString("heartbleed.notification.label")+" "+host;
					nb.appendNotification(label,"heartbleed.notification","chrome://heartbleed/skin/heartbleed_32.png",nb.PRIORITY_CRITICAL_HIGH);
					HeartbleedChecker.heartbleedButton.removeAttribute("class");
					break;
				default:
					//check result for error
					console.log("site result:"+result);
				    if(message) {
//						label=HeartbleedChecker.bundle.getString("heartbleed.caution.label")+" "+message;
//						nb.appendNotification(label,"heartbleed.notification","chrome://heartbleed/skin/heartbleed_32_yellow.png",nb.PRIORITY_WARNING_LOW);
						HeartbleedChecker.heartbleedButton.setAttribute("class","yellow");
				    } else {
				    	HeartbleedChecker.heartbleedButton.setAttribute("class","green");
				    }
					break;
			}
		},
		
		enable:function() {
			HeartbleedCheckerBackgound.enabled=document.getElementById("chkEnabled").checked;
			console.log("HeartbleedCheckerBackgound.enabled:"+HeartbleedCheckerBackgound.enabled);
			
		}
};

//overlay events
window.addEventListener("load",HeartbleedChecker.init,false);
window.addEventListener("unload",HeartbleedChecker.destroy,false);

