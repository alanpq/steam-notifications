const https = require('https');
const fs = require('fs');

const download = function(url, dest, cb) {
  let file = fs.createWriteStream(dest);
  let request = https.get(url, function(response) {
    response.pipe(file);
    file.on('finish', function() {
      file.close(cb);  // close() is async, call cb after close completes.
    });
  }).on('error', function(err) { // Handle errors
    fs.unlink(dest); // Delete the file async. (But we don't check the result)
    if (cb) cb(err.message);
  });
};

const exec = require('child_process').exec;
// const myShellScript = exec('sh doSomething.sh /myDir');

const SteamUser = require('steam-user');
const client = new SteamUser();

const ui = require('./ui')

var LOGGED_IN = false;

// ui.login((u,p) => {
//     client.logOn({
//         "accountName": u,
//         "password": p
//     });
// })

// ui.login((u,p) => {
//     console.log(u,p)
//     setTimeout(()=>{
//     client.logOn({
//         "accountName": u,
//         "password": p
//     })},10)
//     ui.error()
// })

// client.logOn({
// 	"accountName": "letrollerman",
// 	"password": ""
// });

console.log('NodeJS child active!')

process.stdin.on('data', function (text) {
    console.log('received data:', text.toString());
    try {
        let req = JSON.parse(text.toString())
        console.log(Object.keys(req))
        if(req["type"] != undefined) {
            console.log(req.type)
            switch(req.type) {
                case 0: // login with credentials
                    client.logOn({
                        "accountName": req.username,
                        "password"   : req.password
                    })
                    // console.log("InvalidPassword")
                    // console.log("SteamGuardReq")
                    // console.log('logged in: true')
                break;
                case 1: // get current state
                    console.log("logged in:", LOGGED_IN)
                break;
                case 2: // steam guard input
                    if(steamGuardCB != null) {
                        steamGuardCB(req.code)
                    }
                break;
            }
        } else {
            console.error('Request type not found!')
        }
    } catch (error) {
        console.error('Invalid JSON!')
        console.error(error.message)
    }
});

var steamGuardCB = null;

client.on('loggedOn', function(details) {
	console.log("Logged into Steam as " + client.steamID.getSteam3RenderedID());
	//client.setPersona(SteamUser.EPersonaState.Online);
	//client.gamesPlayed(440);
});

client.on('steamGuard', (domain, cb) => {
    console.log('SteamGuardReq')
    steamGuardCB = cb;
})

client.on('user', (user) => {
    // console.log(user)
})

client.on('friendPersonasLoaded', () => {
    // console.log(client.users)
})

client.on('myFriends', () => {
    console.log("sasd");
    console.log(client.myFriends[0])
})


client.on('friendMessage', function(steamID, message) {
    let user = client.users[steamID]
    console.log("Friend message from " + steamID + ": " + message);
    let path = `/tmp/${steamID}`
    download(user.avatar_url_icon, path, () => {
        console.log('file downloaded')
        exec(`dunstify -a Steam -u normal -i ${path} "Message from ${user.player_name}:" "${message}" > /tmp/dunsty.log`)
    })
});

client.on('error', function(e) {
	// Some error occurred during logon
    console.log(e.message);
    // ui.error(e);
});

client.on('webSession', function(sessionID, cookies) {
    console.log("Got web session");
    console.log("logged in: true")
	// Do something with these cookies if you wish
});

client.on('newItems', function(count) {
	console.log(count + " new items in our inventory");
});

client.on('emailInfo', function(address, validated) {
	console.log("Our email address is " + address + " and it's " + (validated ? "validated" : "not validated"));
});

client.on('wallet', function(hasWallet, currency, balance) {
	console.log("Our wallet balance is " + SteamUser.formatCurrency(balance, currency));
});

client.on('accountLimitations', function(limited, communityBanned, locked, canInviteFriends) {
	var limitations = [];

	if (limited) {
		limitations.push('LIMITED');
	}

	if (communityBanned) {
		limitations.push('COMMUNITY BANNED');
	}

	if (locked) {
		limitations.push('LOCKED');
	}

	if (limitations.length === 0) {
		console.log("Our account has no limitations.");
	} else {
		console.log("Our account is " + limitations.join(', ') + ".");
	}

	if (canInviteFriends) {
		console.log("Our account can invite friends.");
	}
});

client.on('vacBans', function(numBans, appids) {
	console.log("We have " + numBans + " VAC ban" + (numBans == 1 ? '' : 's') + ".");
	if (appids.length > 0) {
		console.log("We are VAC banned from apps: " + appids.join(', '));
	}
});

client.on('licenses', function(licenses) {
	console.log("Our account owns " + licenses.length + " license" + (licenses.length == 1 ? '' : 's') + ".");
});

/*

'76561198393404211':
   { rich_presence: [],
     player_name: 'SKY ma GUY',
     avatar_hash:
      <Buffer 99 7a f2 2e fa 38 58 8f ef e1 33 e5 fe 53 52 07 30 76 72 6f>,
     last_logoff: 2019-11-16T12:12:52.000Z,
     last_logon: 2019-11-16T22:47:09.000Z,
     last_seen_online: 2019-11-16T12:12:52.000Z,
     avatar_url_icon:
      'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/99/997af22efa38588fefe133e5fe5352073076726f.jpg',
     avatar_url_medium:
      'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/99/997af22efa38588fefe133e5fe5352073076726f_medium.jpg',
     avatar_url_full:
      'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/99/997af22efa38588fefe133e5fe5352073076726f_full.jpg' } }
*/