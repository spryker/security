<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductReviewGui\Communication\Controller;

use Generated\Shared\Transfer\ProductReviewTransfer;
use Spryker\Service\UtilText\Model\Url\Url;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\ProductReviewGui\Communication\ProductReviewGuiCommunicationFactory getFactory()
 */
class DeleteController extends AbstractController
{

    const PARAM_ID = 'id';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $idProductReview = $this->castId($request->query->get(static::PARAM_ID));

        $productSetTransfer = new ProductReviewTransfer();
        $productSetTransfer->setIdProductReview($idProductReview);

        $this->getFactory()
            ->getProductReviewFacade()
            ->deleteProductReview($productSetTransfer);

        $this->addSuccessMessage(sprintf(
            'Product Review #%d deleted successfully.',
            $productSetTransfer->getIdProductReview()
        ));

        return $this->redirectResponse(
            Url::generate('/product-review-gui')->build()
        );
    }

}
