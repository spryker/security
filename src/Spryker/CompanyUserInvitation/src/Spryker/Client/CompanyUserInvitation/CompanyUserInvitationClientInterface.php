<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\CompanyUserInvitation;

use Generated\Shared\Transfer\CompanyUserInvitationCollectionTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationGetCollectionRequestTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationImportRequestTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationImportResponseTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationSendBatchResponseTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationSendRequestTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationSendResponseTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationUpdateStatusRequestTransfer;
use Generated\Shared\Transfer\CompanyUserInvitationUpdateStatusResponseTransfer;
use Generated\Shared\Transfer\CompanyUserTransfer;

interface CompanyUserInvitationClientInterface
{
    /**
     * Specification:
     * - Imports company user invitations to the persistence with status new.
     * - The invitations are assigned to the company user that executed the import action.
     * - The response contains the result of the operation as well as error messages for not imported company user invitations.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserInvitationImportRequestTransfer $companyUserInvitationImportRequestTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserInvitationImportResponseTransfer
     */
    public function importCompanyUserInvitations(
        CompanyUserInvitationImportRequestTransfer $companyUserInvitationImportRequestTransfer
    ): CompanyUserInvitationImportResponseTransfer;

    /**
     * Specification:
     * - Retrieves a company user invitation collection by the criteria defined in the request.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserInvitationGetCollectionRequestTransfer $companyUserInvitationGetCollectionRequestTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserInvitationCollectionTransfer
     */
    public function getCompanyUserInvitationCollection(
        CompanyUserInvitationGetCollectionRequestTransfer $companyUserInvitationGetCollectionRequestTransfer
    ): CompanyUserInvitationCollectionTransfer;

    /**
     * Specification:
     * - Sends the company user invitation specified in the request.
     * - Sends Emails to the recipient defined in the company user invitation.
     * - Changes the status of the company user invitation from new to sent
     * - The response contains the result of the operation.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserInvitationSendRequestTransfer $companyUserInvitationSendRequestTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserInvitationSendResponseTransfer
     */
    public function sendCompanyUserInvitation(
        CompanyUserInvitationSendRequestTransfer $companyUserInvitationSendRequestTransfer
    ): CompanyUserInvitationSendResponseTransfer;

    /**
     * Specification:
     * - Sends all invitations with status new that were imported by the specified company user.
     * - Sends Emails to the recipients defined in each invitation.
     * - Changes the status of the company user invitations from new to sent
     * - The response contains the result of the operation as well as error messages for not sent company user invitations.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserInvitationSendBatchResponseTransfer
     */
    public function sendCompanyUserInvitations(
        CompanyUserTransfer $companyUserTransfer
    ): CompanyUserInvitationSendBatchResponseTransfer;

    /**
     * Specification:
     * - Updates the status of a company user invitation based on the statusKey defined in the request.
     * - The response contains the result of the operation as well as the updated company user invitation.
     * - This method is also used to soft delete company user invitations.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserInvitationUpdateStatusRequestTransfer $companyUserInvitationUpdateStatusRequestTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserInvitationUpdateStatusResponseTransfer
     */
    public function updateCompanyUserInvitationStatus(
        CompanyUserInvitationUpdateStatusRequestTransfer $companyUserInvitationUpdateStatusRequestTransfer
    ): CompanyUserInvitationUpdateStatusResponseTransfer;

    /**
     * Specification:
     * - Retrieves a company user invitation by hash.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserInvitationTransfer $companyUserInvitationTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserInvitationTransfer
     */
    public function getCompanyUserInvitationByHash(
        CompanyUserInvitationTransfer $companyUserInvitationTransfer
    ): CompanyUserInvitationTransfer;
}
