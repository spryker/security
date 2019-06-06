/**
 * Copyright (c) 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

'use strict';

/**
 * @param {string} validFromSelector
 * @param {string} validToSelector
 *
 * @return {void}
 */
function initialize(validFromSelector, validToSelector) {
    initDatePicker(validFromSelector, function(e) {
        var selectedDate = $(validFromSelector).datepicker('getDate');
        if (!selectedDate) {
            return;
        }

        selectedDate.setDate(selectedDate.getDate() + 1);
        $(validToSelector).datepicker('option', 'minDate', selectedDate);
    });

    initDatePicker(validToSelector, function() {
        var selectedDate = $(validToSelector).datepicker('getDate');
        if (!selectedDate) {
            return;
        }

        selectedDate.setDate(selectedDate.getDate() - 1);
        $(validFromSelector).datepicker('option', 'maxDate', selectedDate);
    });
}

/**
 * @param {string} nodeSelector
 * @param {function} onCloseCallback
 *
 * @return {void}
 */
function initDatePicker(nodeSelector, onCloseCallback) {
    $(nodeSelector).datepicker({
        dateFormat: 'yy-mm-dd',
        changeMonth: true,
        changeYear: true,
        numberOfMonths: 2,
        defaultDate: 0,
        onClose: onCloseCallback
    });
}

module.exports = {
    initialize: initialize
};
