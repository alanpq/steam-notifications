const https = require('https');
const fs = require('fs');

const download = function(url, dest, cb) {
  let file = fs.createWriteStream(dest);
  let request = https.get(url, function(response) {
    response.pipe(file);
    file.on('finish', function() {
      file.close(cb);
    });
  }).on('error', function(err) {
    fs.unlink(dest);
    if (cb) cb(err.message);
  });
};

const exec = require('child_process').exec;

const SteamUser = require('steam-user');
const client = new SteamUser();

const ui = require('./ui')

var LOGGED_IN = false;


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
});

client.on('steamGuard', (domain, cb) => {
    console.log('SteamGuardReq')
    steamGuardCB = cb;
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
    console.log(e.message);
});

client.on('webSession', function(sessionID, cookies) {
    console.log("Got web session");
    console.log("logged in: true")
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