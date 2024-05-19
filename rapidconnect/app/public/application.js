$(document).ready(function() {

  $('.delete-target').on('click', function() {
    var btn = $(this);
    var type = btn.data('type');
    bootbox.dialog({
      message: 'Are you sure you wish to delete this '+type+'?',
      buttons: {
        delete: {
          'label' : 'Delete '+type,
          'className' : 'btn-danger',
          'callback': function() {
            $('#'+btn.data('target')).submit();
          }
        },
        cancel: {
          'label' : 'Cancel',
          'className' : 'btn-default',
          'callback': function() {
          }
        }
      }
    });
  });

  $('.toggle-target').on('click', function() {
    var btn = $(this);
    var type = btn.data('type');
    bootbox.dialog({
      message: 'Are you sure you wish to change the state of this application to '+type+'?',
      buttons: {
        setas: {
          'label' : 'Set as '+type,
          'className' : 'btn-info',
          'callback': function() {
            $('#'+btn.data('target')).submit();
          }
        },
        cancel: {
          'label' : 'Cancel',
          'className' : 'btn-default',
          'callback': function() {
          }
        }
      }
    });
  });

  $("#orgselect").attr("selectedIndex", -1);

  $('.validate').validate({
    ignore: ":disabled",
    keyup: true,
    focusout: false,
    focusInvalid:true,
    errorElement: "div",
    wrapper: "div",
    errorPlacement: function(error, element) {
      error.css('margin-bottom', '12px');

      error.addClass('text-error');
      element.parent().append(error);
    }
  });
});
