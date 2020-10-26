async function loadSites() {
    var objs = await getAllSites()
    var keys = Object.keys(objs)
    var values = Object.values(objs)
    let secure = " "
    let insecure=" "
    for (let i = 0; i < keys.length; i++) {
        let dns_info = ""
        let dns_record = values[i]["DNSRecord"]
        if (dns_record && dns_record["Answer"]) {
            let data = dns_record["Answer"]
            
            for(let value of data){
                dns_info+=`<li class="data">${value.data}</li>`
            }
        }
        
        let style=""
        values[i].secure? style=`"background-color:#F0EFEB"`: style=`"background-color:#fce7e4"`
        let text = `<div class="option-container">
            <div class="options">
                <div class="site-title" style=${style}>
                    <h3 class="site">${keys[i]} </h3>
                </div>
                <div class="site-body">
                    <ul class="dns">
                        <li class="name">${values[i].name} </li>
                        <li class="data_content"> Data 
                            <div class="dns-info">
                                <ul class="dns_record">
                                    ${dns_info}
                                </ul>
                            </div>
                        </li>
                    </ul>
                </div>
            </div>
        </div>`
        
        if(values[i].secure){
            secure += text;
        }else{
            insecure+=text;
        }
        
    }

    document.getElementById("secure").innerHTML += secure
    document.getElementById("insecure").innerHTML += insecure

}



function getAllSites() {
    return new Promise(function (resolve) {
        chrome.storage.local.get(null, function (obj) {
            resolve(obj)
        })
    });
}



document.addEventListener('DOMContentLoaded', function () {
    loadSites();
})