/*
To run the script:
  google-chrome --remote-debugging-port=9222 &
  node mine_crawl.js [target-url]
*/

/*
  Modules import
*/
const CDP = require('chrome-remote-interface');
const { URL } = require('url');
const path = require('path');
const md5 = require('md5');
const fs = require('fs');
const os = require('os');
const ps = require('ps-node');
const usage = require('usage');
const request = require('request');
const atob = require('atob');
var validUrl = require('valid-url');


var noMedia = false;
var deepCrawlFlag = true;
var deepIdx = 0;
var maxDepth = 0;
var maxDepthFlag = false;
var logErrorFlag = false;
var loadTimeOut = 4000;
var newDomsList;
var browser = "chrome";
var mainFolder = "./";
var currFolder = "./";
var dumpPath = "./"; 
var errorLog = "./errorsLog";
var crawlStatusLog = "./status";
var popPages = "./popPages";

//Debug enabled
var DB = false;
var DBv = false; //verbose debugging
var NOut = true;
var NoScript = true;
/*
  Console log debugging messages wrapper
*/
function db_out(message,select){

  if(select == 1 && DB)
    console.log(message);
  else if(select == 2  && DBv)
    console.log(message);
  else if(select == 0)
    console.log(message);
}

function replaceAll(str, find, replace) {
    return str.replace(new RegExp(find, 'g'), replace);
}

function crawlUrl(targetUrl,callback){
  const folder = path.join(mainFolder, replaceAll(targetUrl.pathname,'/','[esc]') + 
    replaceAll(targetUrl.search,'/','[esc]'));
  if(folder.length > 250){ folder = folder.substring(0,249);}
  currFolder = folder;
  try{
    fs.mkdirSync(folder);
  }catch(err){
    var errorString = "Folder already present: " + folder;
      if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
        else db_out(errorString,0);
      callback();
      return
  }
  const media = path.join(folder,"media/");
  if(!noMedia) fs.mkdirSync(media);
  const requests = path.join(folder,'requests');
  const WS = "WSdump";
  const cpuUse = path.join(folder,'cpuUsage');
  const newDoms = path.join(folder,'newDomains');
  const htmlPage = path.join(folder, 'full.html');
  const allcookies = path.join(folder, 'cookies');
  const servworkers = path.join(folder, 'serviceworkes');
  var currTab;

  if(logErrorFlag){
    fs.appendFile(errorLog,"\nErrors from: " + targetUrl.href, function(err){});
  }
  /*
    Chrome Debugging Protocol instance
  */
  CDP.New().then( (tab) =>{
  currTab = tab;
  CDP((client) => {

      // extract domains
      const {Network, Page, 
      DOM, Runtime, Performance, Target} = client;

      var downloadFile = {}; // to download list
      var downloadWFile = {}; // service workers to download files list
      var targetList = [];
      var targetSList = [];
      var linksChecked = 0; // links checks counter
      var htmlScripts = 0; // html scripts checks counter
      var tid = 0; // transactions Ids for workers messages

      // Enable target discovery and auto attachment to intercept TargetAttached events
      Target.setAutoAttach({autoAttach:true, waitForDebuggerOnStart: false})
      Target.setDiscoverTargets({discover: true});

      /*
        Final Callback
      */
      function callbackClose(){
        db_out("Links finsihed?:" + linksChecked + " script finished?:" + htmlScripts,1);
          if (linksChecked && htmlScripts == 'finished'){
              //Testing the output of the performance monitoring functions 
              try{
                CDP.Close({id: currTab.id});
                client.close();
                db_out("BROWSING: end... client closed",1);
                fs.appendFileSync(crawlStatusLog,targetUrl.href + ", Crawl-complete\n", function(err){});
                callback();
              }catch(err){
                var errorString = "CallBackClose: " + err;
                if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                else db_out(errorString,1);
                callback();
              }
          }
      }


      /*
        Target event handlers
      */
      Target.targetCreated((params) => {
        db_out("Target Created: " + params.targetInfo.url + " (" + params.targetInfo.type + ")",1);
        if(params.targetInfo.type == "page" && (params.targetInfo.url != "about:blank" || params.targetInfo.url != "")) 
          fs.appendFileSync(popPages, params.targetInfo.url + "\n", function(err){});
        });

      // Enable networking events from new ServiceWorkes
      Target.attachedToTarget(({sessionId, targetInfo}) => {
          targetList.push(targetInfo.targetId);
          targetSList.push(sessionId);
          if(targetInfo.type != 'page'){
            db_out("ATTACHED " + sessionId + ": " + targetInfo.url,1);
            fs.appendFileSync(servworkers, "ATTACHED " + sessionId + ": " + targetInfo.url + "\n", function(err){});
          }
          else{
            db_out("PAGE " + sessionId + ": " + targetInfo.url,1);
            fs.appendFileSync(servworkers, "PAGE " + sessionId + ": " + targetInfo.url + "\n", function(err){});          
          }
          fs.appendFileSync(servworkers, "ATTACHED " + sessionId + ": " + targetInfo.url + "\n", function(err){});
          Target.sendMessageToTarget({
              sessionId,
              message: JSON.stringify({ // <-- a JSON string!
                  id: tid++,
                  method: 'Network.enable'
              })
          }).catch(function(error) { 
            var errorString = "Send Network.enable to worker: " + error;
            if(logErrorFlag){fs.appendFile(errorLog, errorString, function(err){});}
            else db_out(errorString,1);
          });
          Target.sendMessageToTarget({
              sessionId,
              message: JSON.stringify({ // <-- a JSON string!
                  id: tid++,
                  method: 'Debugger.enable'
              })
          }).catch(function(error) {
            var errorString = "Send Network.enable to worker: " + error;
            if(logErrorFlag){fs.appendFile(errorLog, errorString, function(err){});}
            else db_out(errorString,1);
          });;
      });

      // Let's deal with separate ServiceWorkers events 
      Target.receivedMessageFromTarget(({sessionId, message}) => {
          const {id, method, result, params} = JSON.parse(message); // <-- a JSON string!
          //Check if we have any reply messages received from the worker
          if(id){
            //Dump the worker body response
            if(result){ 
              if(result.base64Encoded){
                fs.appendFileSync(path.join(folder,"WorkerRq-" + downloadWFile[id]),
                atob(result.body), function(err){});              
              }else{
                fs.appendFileSync(path.join(folder,"WorkerRq-" + downloadWFile[id]),
                result.body, function(err){});              
              }

            }
          }
          //Check if we have any events from the worker
          switch (method) {
          case 'Network.requestWillBeSent':{
                  const {request: {url}} = params;
                  fs.appendFile(requests, params.requestId +
                  ',' + params.request.url + '\n', function(err){});
                  db_out(`WORKER REQUEST: ${sessionId}: ${url}` + " RequestId:" + params.requestId,1);
                  break;
              }
          case "Network.responseReceived":{
            db_out("WORKER RECEIVED: " + params.requestId + " " + params.type,1);
            downloadFile[params.requestId] = params.type;
            break;

          }
          case "Network.loadingFinished" :{
            db_out("WORKER LOADED: " + params.requestId + " " + " id:" + tid,1);
            downloadWFile[tid] = tid;
            if (downloadFile[params.requestId]) {
              Target.sendMessageToTarget({
                sessionId,
                message: JSON.stringify({
                  id : tid++,
                  method: "Network.getResponseBody",
                  params: {requestId: params.requestId}
                })
              }).catch(function(error) {
                var errorString = "Send Network.getResponseBody to worker: " + error;
                if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                else db_out(errorString,1);
              });
            }
            break;
          }
          default: //no default
        }
      });

      /*
        Setup Network events handlers
      */

      //This is triggered when the client initiate a request
      // it dumps all the network documents requests from initiated by the client 
     Network.requestWillBeSent((params) => {
          db_out("REQUEST: " + params.request.url,2);
          fs.appendFile(requests, params.requestId +
          ',' + params.request.url + '\n', function(err){});
      });


      //This is triggered when a http response is received
      Network.responseReceived((params) => {   
          	//Better to log every response
            if((params.type === 'Image' || 
              params.type === "Media" ||
              params.type === "Font" ||
              params.type === "Stylesheet") && noMedia){}
        	  else{
              downloadFile[params.requestId] = params.type;
              db_out("RECEIVED: " + params.requestId + " type: " + downloadFile[params.requestId],2);
            } 
      });

      //This is triggered when a document is loaded into the client
      // it dumps the loaded documents (of every kind - so even wasm and js)
      Network.loadingFinished((params) => {
          if (downloadFile[params.requestId]) {
            db_out("LOADED: " + params.requestId + " type: " + downloadFile[params.requestId],2);
              Network.getResponseBody({
                  requestId: params.requestId
              }).then(response => {
                  var fol = (downloadFile[params.requestId] === "Media"
                             || downloadFile[params.requestId] === "Image")? media:folder;
                  if(response.base64Encoded){
                    fs.appendFileSync(path.join(fol, downloadFile[params.requestId] + "-" + params.requestId),
                    atob(response.body), function(err){});
                  }else{
                    fs.appendFileSync(path.join(fol, downloadFile[params.requestId] + "-" + params.requestId),
                    response.body, function(err){});                  
                  }

              }).catch(function(error) {
                var errorString = "Loading finished - Network.getResponseBody: " + error;
                if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                else db_out(errorString,1);
              });
          }
      });

      // Log a WebSocket creation
      Network.webSocketCreated((params) => {
        db_out("WS CREATION:" + params.url,2);
        fs.appendFileSync(path.join(folder, WS),
        "[WS-Creation] " + params.url, function(err){});
      });

      // Log when a new frame is received from a WS
      Network.webSocketFrameReceived((params) => {
        db_out("WS: RECEIVED:" + params.response.payloadData,2);
        fs.appendFileSync(path.join(folder, WS),
        "\n[IN]" + params.response.payloadData, function(err){});    
      });

      // Log when a new frame is sent to a WS
      Network.webSocketFrameSent((params) => {
        db_out("WS: SENT:" + params.response.payloadData,2);
        fs.appendFileSync(path.join(folder, WS),
        "\n[OUT]" + params.response.payloadData, function(err){}); 
      });

      /*
        Setup Page events handlers
      */
      //This is triggered when all the elements in a page are loaded
      Page.loadEventFired(() => {
          setTimeout(function() {
              logcpu(browser);
              obtainPage();
              obtainCookies();
              obtainNew(callbackClose);
          }, loadTimeOut)
      });

      /*
        This function dump the main html page of the target dom
      */
      function obtainPage(){
          Runtime.evaluate({
              expression: 'document.documentElement.outerHTML'
          }).then(result => {
            const html = result.result.value;
            fs.appendFileSync(htmlPage, html, function(err){});
            db_out("HTML: page dumped",1);
          }); 
      }

      /*
        This function log all the active cookies
      */
      function obtainCookies(){
        Network.getAllCookies().then(
          cookies => {
            fs.appendFileSync(allcookies, JSON.stringify(cookies), function(err){});
            db_out("COOKIES: dumped",1);
          });
      }

      /*
        This function extract all the reachable domains and scripts from a page
        newdom is set to true if we want to log the reachable new domains
      */
      function obtainNew(callback) {
          DOM.getDocument().then(doc =>{
              if(NoScript) htmlScripts = 'finished';
              else extractScript(doc.root.nodeId,callback);
              obtainDOM(callback, doc);
          });
      }
      /*
        This function extract the new domains from the html page
      */
      function obtainDOM(callback, doc){
            DOM.querySelectorAll({nodeId : doc.root.nodeId,
              selector : 'a[href]'}).then(links =>{
                 if(Object.keys(links.nodeIds).length === 0){
                  linksChecked = 'finished';
                  callback();
                 }
                 for (let link of links.nodeIds) {
                     DOM.resolveNode({nodeId : link
                     }).then(rObject => {
                        Runtime.getProperties({
                        objectId: rObject.object.objectId
                        }).then(properties => {
                           var nDom = properties.result.find(function (obj)
                           { return obj.name === 'href'; }).value.value
                           nDom = new URL(nDom);
                           if (nDom.host == targetUrl.host) {
                              fs.appendFileSync(newDoms, nDom.href + '\n',
                              function(err){});
                           }
                           linksChecked++;
                           if (linksChecked == links.nodeIds.length) {
                                  linksChecked = 'finished';
                                  db_out("NEW DOMS: collected",1);
                                  callback();
                           }

                        }).catch(function(error) {
                          linksChecked++;
                          if (linksChecked == links.nodeIds.length) {
                                  linksChecked = 'finished';
                                  db_out("NEW DOMS: collected",1);
                                  callback();
                          }
                              var errorString = "obtainDOM - getProperties: " + error;
                              if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                              else db_out(errorString,1);
                        });
                     }).catch(function(error) {
                            var errorString = "obtainDOM - resolveNode: " + error;
                            if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                            else db_out(errorString,1);
                      });
                  }
              }).catch(function(error) {
                    var errorString = "obtainDOM - querySelectorAll: " + error;
                    if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                    else db_out(errorString,1);
              });
      }
      /*
        This function extract js files from <script> tags
      */
      function extractScript(docId,callback) {
          var countHtml = 0;
          DOM.querySelectorAll({nodeId : docId,
          selector : 'script'}).then(scripts =>{
            if(Object.keys(scripts.nodeIds).length === 0){
              htmlScripts = 'finished';
              callback();
            } 
             for (let script of scripts.nodeIds) {
                 DOM.resolveNode({nodeId : script
                 }).then(rObject => {
                     Runtime.getProperties({
                     objectId: rObject.object.objectId
                     }).then(properties => {
                         var scriptCode = properties.result.find(function (obj)
                         { return obj.name === 'innerText'; }).value.value
                         if (scriptCode != ''){
                             countHtml++;
                             fs.appendFileSync(path.join(folder,
                             'html' + countHtml), scriptCode,
                             function(err){});
                         }
                         htmlScripts++;
                         if (htmlScripts == scripts.nodeIds.length) {
                             htmlScripts = 'finished';
                             db_out("DOM SCRIPTS: collected",1);
                             callback();
                         }
                      }).catch(function(error) {
                        htmlScripts++;
                        if (htmlScripts == scripts.nodeIds.length) {
                             htmlScripts = 'finished';
                             db_out("DOM SCRIPTS: collected",1);
                             callback();
                         }
                              var errorString = "obtainDOM - getProperties: " + error;
                              if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                              else db_out(errorString,1);
                      });
                  }).catch(function(error) {
                        var errorString = "obtainDOM - resolveNode: " + error;
                        if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                        else db_out(errorString,1);
                  });
              }
          }).catch(function(error) {
                var errorString = "Extract script - querySelectorAll: " + error;
                if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
                else db_out(errorString,1);
          });
      }

      /*
        This function logs the cpu usage info for every process matching
        the input string "program"
      */
      function logcpu(program){
        var  i = 0;
        // A simple pid lookup 
        ps.lookup({
          command: program,
          }, function(err, resultList ) {
          if (err) {
              throw new Error( err );
          }
          //Look up cpu and dump to file
          resultList.forEach(function( process ){
            if( process ){
              usage.lookup(process.pid, function(err, usageInfo) {
                if(usageInfo){
                  var out = program + " t."+ i++ + " cpu: " + usageInfo.cpu + "\n";
                  fs.appendFileSync(cpuUse, out, function(err){});
                } else { db_out("UsageInfo lookup failed",1) }
              });
            }
          });
        });
        db_out("CPU USAGE: logged",1);
      }

      // Enable the events and start navigating the page
      Promise.all([
          DOM.enable(),
          Network.enable(),
          Page.enable(),
          Runtime.enable(),
      ]).then(() => {
          // Clear browser cache
          if(Network.canClearBrowserCache()) {
            Network.clearBrowserCache() 
            db_out("CACHE: cleared",1);
          }
          // Coear browser cookies
          if(Network.canClearBrowserCookies()) {
            Network.clearBrowserCookies();
            db_out("COOKIES: cleared",1);
          }
          //start navigation
          db_out("BROWSING: Navigation started: " + targetUrl,1);
          return Page.navigate({url: targetUrl});
      }).catch((err) => {
        if(logErrorFlag){
          fs.appendFile(errorLog,err, function(err){});
        }else console.error(err);
          CDP.Close({id: currTab.id});
          client.close();
      });

  }).on('error', (err) => {
    // cannot connect to the remote endpoint;
      if(logErrorFlag){
        fs.appendFile(errorLog,err, function(err){});
      }else console.error(err);
  })
});
}

function showHelp(){
  console.log("Welcome to Mine Crawl!\n"
              + "usage: node " + process.argv[1] + " [target url] [output path]\n"
              + "\t-h: show help\n"
              + "\t-v: verboselv.1\n"
              + "\t-o: output enabled\n"
              + "\t-vv: verbose lv.2\n"
              + "\t-le: log errors in a separate file\n"
              + "\t-dp: data dump path\n"
              + "\t-nm: dump no media files\n"
              + "\t-t: load page timeout"
              + "\t-md [depth]: max number of links to follow\n"
              + "\t-nf: not follow: crawl only top level url\n"
              + "\t-chromium: using chromium browser (default chrome)\n"
);
}

function isURL(str) {
     var urlRegex = '^(?!mailto:)(?:(?:http|https|ftp)://)(?:\\S+(?::\\S*)?@)?(?:(?:(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[0-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})))|localhost)(?::\\d{2,5})?(?:(/|\\?|#)[^\\s]*)?$';
     var url = new RegExp(urlRegex, 'i');
     return str.length < 2083 && url.test(str);
}

function sort_unique(arr) {
    return arr.sort().filter(function(el,i,a) {
        return (i==a.indexOf(el));
    });
}

function isNumeric(num){
  return !isNaN(num)
}

function getRandomSubarray(arr, size) {
    var shuffled = arr.slice(0), i = arr.length, temp, index;
    while (i--) {
        index = Math.floor((i + 1) * Math.random());
        temp = shuffled[index];
        shuffled[index] = shuffled[i];
        shuffled[i] = temp;
    }
    return shuffled.slice(0, size);
}

function log(out){
  if(!NOut){
    console.log(out);
  }
}

function checkArgs(){
  var args = process.argv.slice(2);

  // Check if the url is reachable
  if(!args){
    log(process.argv[1] + " - ERROR: No url specified")
    showHelp();
    return 0;
  }
  if(args[0] === "-h"){
    showHelp();
    return 0;
  }
  if(!isURL(args[0])){
    log(process.argv[1] + " - ERROR: url not valid: " + args[0])
    return 0;
  }

   if(!args[1]){
    dumpPath = "./";
  }
  else{
    log("Dumping crawled data" + args[1])
    dumpPath =  args[1] + "/";
  }

  /*request(args[0], function (error, response, body) {
    if (!error) { //&& response.statusCode == 200
      return 1;    
    }else{
      console.log(process.argv[1] + " - ERROR: url unreachable")
      return 0;
    }
  })*/

  for(var i = 0; i < args.length; i++){
    switch(args[i]){
      case '-h':{
        showHelp();
        break;
      }
      case '-v':{
        DB = true;
        break;
      }
      case '-o':{
        NOut = false;
        break;
      }
      case '-vv':{
        DB = true;
        DBv = true;
        break;
      } 
      case '-nf':{
        deepCrawlFlag = false;
        break;
      }
      case '-nm':{
        noMedia = true;
        break
      }
      case '-chromium':{
        browser = "chromium";
        break;
      }
      case '-le':{
        logErrorFlag=true;
        break;
      }
      case '-t':{
        if(((i+1) >= args.length) || !isNumeric(args[i+1])){
          log("Args error -t: no timeout specified");
          return 0;
        }
        if(Number(args[i+1]) > 0){
          i++;
          loadTimeOut = Number(args[i]);
          break;
        }else{
          log("Args error -md: negative timeout");
          return 0;
        }        
      }
      case '-md':{
        if(((i+1) >= args.length) || !isNumeric(args[i+1])){
          log("Args error -md: no max depth specified");
          return 0;
        }
        if(Number(args[i+1]) > 0){
          i++;
          maxDepth = Number(args[i]);
          maxDepthFlag = true;
          break;
        }else{
          log("Args error -md: negative depth specified");
          return 0;
        }

      }
    }
  };
  return 1;
}
/*
  Main 
*/
function main(){

  function deepCrawl(){
    if(deepIdx == 0){
      var newDomPath = path.join(currFolder,"newDomains");
      if(fs.existsSync(newDomPath)){
        newDomsList = sort_unique(fs.readFileSync(newDomPath, 'utf8').split("\n"));
        if(maxDepthFlag && newDomsList.length > maxDepth){
          newDomsList = getRandomSubarray(newDomsList,maxDepth);
        }
      }else{
        newDomsList = [];
	      log("No new domains found in the target url!");
      }
    }
    //Make sure is a valid url
    while(deepIdx < newDomsList.length && !isURL(newDomsList[deepIdx])){
      deepIdx++;
    }
    if(deepIdx < newDomsList.length){
      var targetDom = new URL(newDomsList[deepIdx++]);
      log("\n\nCrawling new reachable url: " + targetDom + " .....\n\n");
      if(deepIdx == newDomsList.length)
        crawlUrl(targetDom,crawlEnd); 
      else
        crawlUrl(targetDom,deepCrawl);
    }else
      crawlEnd();
  }

  function crawlEnd(){
    log("\nMine Crawl Quitting....\n");
  }

  if(!checkArgs()){
    return;
  }
  db_out("VALIDATION: args validated and url reachable",1);

  /*
    Setup main folder
  */
  const dom = new URL(process.argv[2]);
  mainFolder = dumpPath + dom.hostname;

  if(logErrorFlag){
    errorLog = dumpPath + "errors";
  }
  crawlStatusLog = dumpPath + "status";
  popPages = mainFolder + "/popPages";

  try{
    fs.mkdirSync(mainFolder);
  }catch(err){
    log("Folder already present, Quitting...");
    var errorString = dom.hostname + ": Folder already present, Quitting...";
    if(logErrorFlag){fs.appendFile(errorLog,errorString, function(err){});}
    //return;
  }

  log("********\t Welcome to Mine Crawl!\t********\n\n"
              + "Top level Domanin crawl... " + dom);
  //Crawl first Level
  if(deepCrawlFlag){  crawlUrl(dom,deepCrawl); }
  else { crawlUrl(dom, crawlEnd); }
}

main();
