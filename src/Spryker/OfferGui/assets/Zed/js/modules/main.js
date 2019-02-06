/**
 * Copyright (c) 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

'use strict';

require('../../scss/main.scss');

$(document).ready( function () {

    var contactDate = $('#edit_offer_contactDate');

    contactDate.datepicker({
        dateFormat: 'yy-mm-dd',
        changeMonth: true,
        numberOfMonths: 3
    });

    $('form[name="edit_offer"] input').on('keyup keypress', function(e) {
        return e.which !== 13;
    });

});
