<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Payolution\Business\Api\Adapter\Http;

class RefundAdapterMock extends AbstractAdapterMock
{
    /**
     * @return array
     */
    public function getSuccessResponse()
    {
        return 'P3_VALIDATION=ACK' . '&' .
            'IDENTIFICATION_SHOPPERID=790' . '&' .
            'CLEARING_DESCRIPTOR=9053.8347.7922 inv-ins-test-default 795' . '&' .
            'PROCESSING_CONNECTORDETAIL_ConnectorTxID1=Tx-cm3yprrtggt' . '&' .
            'TRANSACTION_CHANNEL=8a82941832d84c500132e875fc0c0648' . '&' .
            'PROCESSING_REASON_CODE=00' . '&' .
            'PROCESSING_CODE=VA.RF.90.00' . '&' .
            'FRONTEND_REQUEST_CANCELLED=false' . '&' .
            'PROCESSING_REASON=Successful Processing' . '&' .
            'FRONTEND_MODE=DEFAULT' . '&' .
            'CLEARING_FXSOURCE=INTERN' . '&' .
            'CLEARING_AMOUNT=100.00' . '&' .
            'PROCESSING_RESULT=ACK' . '&' .
            'NAME_SALUTATION=NONE' . '&' .
            'PRESENTATION_USAGE=795' . '&' .
            'POST_VALIDATION=ACK' . '&' .
            'CLEARING_CURRENCY=EUR' . '&' .
            'FRONTEND_SESSION_ID=' . '&' .
            'PROCESSING_STATUS_CODE=90' . '&' .
            'PRESENTATION_CURRENCY=EUR' . '&' .
            'PAYMENT_CODE=VA.RF' . '&' .
            'PROCESSING_RETURN_CODE=000.100.112' . '&' .
            'CONTACT_IP=5.145.176.11' . '&' .
            'IDENTIFICATION_REFERENCEID=' . $this->requestData['IDENTIFICATION.REFERENCEID'] . '&' .
            'PROCESSING_STATUS=NEW' . '&' .
            'FRONTEND_CC_LOGO=images/visa_mc.gif' . '&' .
            'PRESENTATION_AMOUNT=100.00' . '&' .
            'IDENTIFICATION_UNIQUEID=8a8294494fd6cc31014fdf6d96ae5657' . '&' .
            // We need to set the request's transaction id to fulfil the foreign-key constraint
            'IDENTIFICATION_TRANSACTIONID=' . $this->requestData['IDENTIFICATION.TRANSACTIONID'] . '&' .
            'IDENTIFICATION_SHORTID=9053.8347.7922' . '&' .
            'CLEARING_FXRATE=1.0' . '&' .
            'PROCESSING_TIMESTAMP=2015-09-18 07:49:05' . '&' .
            'ADDRESS_COUNTRY=DE' . '&' .
            'PROCESSING_CONNECTORDETAIL_PaymentReference=HRJS-BTWL-LDXL' . '&' .
            'RESPONSE_VERSION=1.0' . '&' .
            'TRANSACTION_MODE=CONNECTOR_TEST' . '&' .
            'TRANSACTION_RESPONSE=SYNC' . '&' .
            'PROCESSING_RETURN=Request successfully processed in \'Merchant in Connector Test Mode\'' . '&' .
            'CLEARING_FXDATE=2015-09-18 07:49:05\r\n';
    }

    /**
     * @return array
     */
    public function getFailureResponse()
    {
        return 'TRANSACTION_CHANNEL=8a82941832d84c500132e875fc0c0648' . '&' .
            'PRESENTATION_CURRENCY=EUR' . '&' .
            'IDENTIFICATION_UNIQUEID=8a8294494fd6cc31014fdf878cf50bd0' . '&' .
            'PAYMENT_CODE=VA.RF' . '&' .
            'FRONTEND_CC_LOGO=images/visa_mc.gif' . '&' .
            'PROCESSING_STATUS=REJECTED_VALIDATION' . '&' .
            'CONTACT_IP=5.145.176.11' . '&' .
            'FRONTEND_MODE=DEFAULT' . '&' .
            'FRONTEND_REQUEST_CANCELLED=false' . '&' .
            'PROCESSING_RETURN=referenced session is REJECTED (no action possible).' . '&' .
            'PROCESSING_REASON=Registration Error' . '&' .
            'PROCESSING_STATUS_CODE=70' . '&' .
            'TRANSACTION_MODE=CONNECTOR_TEST' . '&' .
            'IDENTIFICATION_SHOPPERID=808' . '&' .
            'POST_VALIDATION=ACK' . '&' .
            'PROCESSING_TIMESTAMP=2015-09-18 08:17:26' . '&' .
            'PROCESSING_RETURN_CODE=100.350.100' . '&' .
            'RESPONSE_VERSION=1.0' . '&' .
            'IDENTIFICATION_REFERENCEID=' . $this->requestData['IDENTIFICATION.REFERENCEID'] . '&' .
            'TRANSACTION_RESPONSE=SYNC' . '&' .
            'P3_VALIDATION=ACK' . '&' .
            'PROCESSING_CODE=VA.RF.70.64' . '&' .
            'FRONTEND_SESSION_ID=' . '&' .
            'PROCESSING_REASON_CODE=64' . '&' .
            'IDENTIFICATION_SHORTID=2827.4743.7730' . '&' .
            'PRESENTATION_USAGE=813' . '&' .
            'NAME_SALUTATION=NONE' . '&' .
            'PROCESSING_RESULT=NOK' . '&' .
            // We need to set the request's transaction id to fulfil the foreign-key constraint
            'IDENTIFICATION_TRANSACTIONID=' . $this->requestData['IDENTIFICATION.TRANSACTIONID'] . '&' .
            'PRESENTATION_AMOUNT=10000.00' . '&' .
            'ADDRESS_COUNTRY=DE\r\n';
    }
}
