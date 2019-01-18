<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ContentGui\Communication\Controller;

use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * @method \Spryker\Zed\ContentGui\Communication\ContentGuiCommunicationFactory getFactory()
 */
class ListContentController extends AbstractController
{
    /**
     * @return array
     */
    public function indexAction(): array
    {
        $contentTable = $this->getFactory()->createContentTable();

        return $this->viewResponse([
            'contents' => $contentTable->render(),
            'termKeys' => $this->getFactory()->createContentResolver()->getTermKeys(),
        ]);
    }

    /**
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function tableAction(): JsonResponse
    {
        $contentTable = $this->getFactory()->createContentTable();

        return $this->jsonResponse($contentTable->fetchData());
    }
}
