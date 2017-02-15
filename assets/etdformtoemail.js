+function($) {

    function validateEmail(email) {
        var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(email);
    }

    function EtdFormToEmail(element, options) {
        this.options = $.extend({}, EtdFormToEmail.DEFAULTS, options);
        this.$element = $(element);

        this.init();
    }

    EtdFormToEmail.DEFAULTS = {
        i18n: {
            sending: 'Submiting...',
            send: 'Submit',
            thanks: 'Thank you !',
            error: 'An error has occured'
        }
    };

    EtdFormToEmail.prototype.init = function() {

        var self = this;

        this.$element.find('input[type="submit"], button[type="submit"], input[type="image"]').on('click', function() {
            self.$submitSource = $(this);
        });

        this.$element.on('submit', function(e) {
            e.preventDefault();

            if (self.$submitSource) {
                self.$submitSource.prop('disabled', true).text(self.options.i18n.sending);
            }

            var formData = self.$element.serializeArray();

            $
                .post(self.$element.attr('action'), formData)
                .done(function(json) {
                    if (!json.success) {
                        alert(json.message);
                        if (self.$submitSource) {
                            self.$submitSource.prop('disabled', false).text(self.options.i18n.send);
                        }
                    } else {
                        if (self.$submitSource) {
                            self.$submitSource.text(self.options.i18n.thanks);
                            if(json.data[0].message) {
                                $('<span>&nbsp;' + json.data[0].message + '</span>').insertAfter(self.$submitSource);
                            }
                        }
                    }
                    self.$submitSource = null;
                })
                .fail(function() {
                    alert(self.options.i18n.error);
                    if (self.$submitSource) {
                        self.$submitSource.prop('disabled', false).text(self.options.i18n.send);
                    }
                    self.$submitSource = null;
                });

            return false;
        });

    };

    function Plugin(option) {
        return this.each(function() {
            var $this = $(this);
            var data = $this.data('etd.formtoemail');
            var options = typeof option == 'object' && option;

            if (!data) {
                $this.data('etd.formtoemail', (data = new EtdFormToEmail(this, options)));
            }
            if (typeof option == 'string') {
                data[option]();
            }
        });
    }

    $(window).on('load.etd.formtoemail.data-api', function() {
        $('[data-etd="formtoemail"]').each(function() {
            var $form = $(this);
            Plugin.call($form, $form.data());
        });
    })

}(jQuery);
