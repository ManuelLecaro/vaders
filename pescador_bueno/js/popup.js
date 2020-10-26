async function doRegisterURL() {
   var tablink = await getCurrentURL();
   if (isValidURL(tablink)) {
      var url = new URL(tablink);
      var domain = url.hostname
      domain = getDomain(domain)
      var register = await isRegister(domain)
      if (register) {
         confirm("El sitio se encuentra registrado")
         updateDomain(domain, true)
      } else {
         saveURL(domain, true);
      }
   } else {
      confirm('El url no es correcto')
   }
}

async function isRegister(domain) {
   var record = await getRecord(domain)
   return Object.keys(record).length !== 0
}

function getRecord(domain) {
   return new Promise(function (resolve) {
      chrome.storage.local.get(domain, function (obj) {
         resolve(obj)
      })
   })
}

function getCurrentURL() {
   return new Promise(function (resolve) {
      chrome.tabs.getSelected(null, function (tab) {
         resolve(tab.url)
      })
   })
}

function isValidURL(link) {
   try {
      var url = new URL(link)
      if (url.protocol == "chrome:") return false
      return true
   } catch (e) {
      return false
   }
}


async function saveURL(domain, state) {
   var dns = await getDNSRecord(domain)
   var value = {
      name: getDomainName(domain),
      extension: getDomainExtension(domain),
      DNSRecord: dns,
      secure: state
   }
   chrome.storage.local.set({ [domain]: value }, function (obj) { 
      if(state) confirm("Se ha registrado el sitio")
    })
}

function getDomain(domain) {
   var withW = domain.includes("www");
   if (!withW) return domain
   else {
      var index = domain.indexOf(".") + 1;
      return domain.substring(index)
   }
}

function getDomainExtension(domain) {
   var index = domain.lastIndexOf(".")
   return domain.substring(index);
}

function getDomainName(domain) {
   var index = domain.lastIndexOf(".")
   return domain.substring(0, index)
}

async function getDNSRecord(domain) {
   var url = `https://dns.google/resolve?name=${domain}&ct=application/x-javascript&type=255`
   let data = await fetch(url).then(
      value => value.json()
   )
      .then(value => {
         return value;
      })

   return data;
}


async function scanDNS(tablink) {
   var url = new URL(tablink);
   var susp_domain = url.hostname
   var register = await isRegister(susp_domain)
   if (register) {
      var secure= await isSecure(susp_domain);
      secure? updateDomain(susp_domain, true) : alert("El sitio se ha registrado como inseguro previamente")
   } else{
      var isValid = await compareDomain(susp_domain)
      if (!isValid.valid) {
         alert("El sitio parece suplantar al dominio registrado " + isValid.domain)
         registerSuspiciusDomain(susp_domain)
      }
   }
}

async function isSecure(domain){
   var record = await getRecord(domain)
   return record.secure;
}

async function registerSuspiciusDomain(susp_domain) {
   saveURL(susp_domain, false)
}

async function updateDomain(domain, issecure) {
   var obj = await getRecord(domain);
   var values = Object.values(obj)
   if (values.length !== 0) {
      values = values[0]
      var dns = await getDNSRecord(domain)
      var value = {
         name: values.name,
         extension: values.extension,
         DNSRecord: dns, 
         secure: issecure
      }
      chrome.storage.local.set({ [domain]: value }, function (obj) { })
   }
}

async function compareDomain(current_DomainName) {
   var domains = await getAllRecords();
   var values = Object.values(domains)
   var keys = Object.keys(domains)
   for (let i = 0; i < keys.length; i++) {
      let domainName = values[i].name;
      let similarity = similar_text(domainName, getDomainName(current_DomainName));
      if (similarity === 1 && values[i].extension === getDomainExtension(current_DomainName && values[i].secure )) {
         return { valid: true, domain: "" };
      }
      if (similarity >= 0.5) {
         var isValid = await validWebsite(keys[i], current_DomainName, values[i])
         return { valid: isValid, domain: keys[i] }
      }

   }
   return { valid: true, domain: "" }
}



async function validWebsite(domain, current_DomainName, record) {
   let domain_age = await getAge(domain);
   let currentD_age = await getAge(current_DomainName);
   if (!ageUndefined(domain_age, currentD_age) && domain_age != currentD_age && data < 180) {
      return false;
   }
   var dns = await equalDNSRecord(record, current_DomainName)
   var secure = await isSecure(domain)
   return (dns && secure)
}

async function equalDNSRecord(record, susp_domain) {
   let susp_record = await getDNSRecord(susp_domain);
   let record1 = record["DNSRecord"]["Answer"]
   let record2 = susp_record["Answer"]
   if (!record1 || !record2) return false;
   return compareArrays(record1, record2)
}

function compareArrays(array1, array2) {
   if (array1.length !== array2.length) return false
   var result = array1.filter(function (dict1) {
      return array2.some(function (dict2) {
         return dict1.data === dict2.data;
      });
   });
   return result.length === array1.length
}

async function getAge(domain) {
   var url = `https://ipty.de/domage/api.php?domain=${domain}`
   let data = await fetch(url).then(
      value => { return value.json() }
   ).catch(() => { return undefined }
   )
   return data;
}

function ageUndefined(age1, age2) {
   return isNaN(age1) || isNaN(age2)
}

function getAllRecords() {
   return new Promise(function (resolve, reject) {
      chrome.storage.local.get(null, function (obj) {
         resolve(obj)
      })
   });
}




function similar_text(original, name) {
   if (original === null || name === null || typeof original === 'undefined' || typeof name === 'undefined') {
      return 0;
   }

   original += '';
   name += '';

   var pos1 = 0,
      pos2 = 0,
      max = 0,
      originalLength = original.length,
      nameLength = name.length,
      p, q, l, sum;

   max = 0;

   for (p = 0; p < originalLength; p++) {
      for (q = 0; q < nameLength; q++) {
         for (l = 0;
            (p + l < originalLength) && (q + l < nameLength) && (original.charAt(p + l) === name.charAt(q + l)); l++);
         if (l > max) {
            max = l;
            pos1 = p;
            pos2 = q;
         }
      }
   }

   sum = max;

   if (sum) {
      if (pos1 && pos2) {
         sum += this.similar_text(original.substr(0, pos2), name.substr(0, pos2));
      }

      if ((pos1 + max < originalLength) && (pos2 + max < nameLength)) {
         sum += this.similar_text(original.substr(pos1 + max, originalLength - pos1 - max), name.substr(pos2 + max, nameLength - pos2 - max));
      }
   }

   return sum / originalLength;
}

let registerURL = () => {
   var button= document.querySelector('#register-button')
   if(button){
      button.addEventListener('click', doRegisterURL, false)
   }
   
}

document.addEventListener(
   'DOMContentLoaded', function () {
      registerURL();
      chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
         if (changeInfo.status == "complete" && isValidURL(tab.url)) {
            scanDNS(tab.url)
         }
      
      });
   }
)



