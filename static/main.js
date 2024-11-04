$(document).ready(function() {
    var socket = io.connect('http://' + document.domain + ':' + location.port, {
        transports: ['websocket']
    });

    socket.on('connect', function() {
        console.log('Connected to server');
        $('#errorMessages').append('<div class="alert alert-success">Connected to server</div>');
    });

    socket.on('message', function(msg) {
        console.log('Received message:', msg);
        $('#messages').append('<li class="list-group-item">' + msg + '</li>');
    });

    socket.on('connect_error', function(error) {
        console.error('Connection Error:', error);
        $('#errorMessages').append('<div class="alert alert-danger">Connection Error: ' + error + '</div>');
    });

    socket.on('error', function(error) {
        console.error('Error:', error);
        $('#errorMessages').append('<div class="alert alert-danger">Error: ' + error + '</div>');
    });

    socket.on('disconnect', function(reason) {
        console.error('Disconnected:', reason);
        $('#errorMessages').append('<div class="alert alert-warning">Disconnected: ' + reason + '</div>');
    });

    $('#sendButton').click(function() {
        var message = $('#myMessage').val();
        if (message.trim() === '') {
            $('#errorMessages').append('<div class="alert alert-warning">Message cannot be empty</div>');
            return;
        }
        console.log('Sending message:', message);
        socket.send(message);
        $('#myMessage').val('');
    });
});