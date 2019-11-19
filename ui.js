// const gi = require('node-gtk')
// const Gtk = gi.require('Gtk', '3.0')



// var loginTimeoutID;

// var progressers = []

// exports.progress = () => {
//     for(var i = 0; i < progressers.length; i++) {
//         console.log('progress', i)
//         progressers[i].progressPulse()
//     }
//     setTimeout(()=>{}, 1000)
// }

// var error;

// exports.login = (cb) => {
//     gi.startLoop()
//     Gtk.init()
//     console.log('hi')
//     const win = new Gtk.Window()
//     win.setTitle('steam-integration login')
//     win.setResizable(false)
//     win.on('destroy', () => Gtk.mainQuit())
//     win.on('delete-event', () => false)
    
//     win.setDefaultSize(200, 80)
//     const grid = new Gtk.Grid()
    
//     const username = new Gtk.Entry()
//     username.setProgressPulseStep(0.5)
//     const password = new Gtk.Entry()
//     password.setProgressPulseStep(0.5)
//     password.setVisibility(false)
//     const but_login = new Gtk.Button({ label: 'Login' })

//     error = new Gtk.Label({label: ''})
//     but_login.on('button-press-event', () => {
//         clearTimeout(loginTimeoutID)
//         loginTimeoutID = setTimeout(()=>{
//             console.log('press')
//             // username.editable = false
//             // password.editable = false
//             username.setSensitive(false)
//             password.setSensitive(false)
//             progressers.push(username)
//             progressers.push(password)
//             but_login.setSensitive(false)
//             // username.progressPulse()
//             // password.progressPulse()
//             cb(username.getText(), password.getText())
//         }, 2)
//     })
    
//     grid.attach(new Gtk.Label({ label: 'Username' }),0,0,1,1)
//     grid.attach(username,0,1,1,1)
//     grid.attach(new Gtk.Label({ label: 'Password' }),0,2,1,1)
//     grid.attach(password,0,3,1,1)
//     grid.attach(but_login,0,4,1,1)
//     grid.attach(error,0,5,1,1)
    
//     win.add(grid)
//     win.showAll()

//     Gtk.main()
// }

// exports.error = () => {
//     error.setText('test')
// }