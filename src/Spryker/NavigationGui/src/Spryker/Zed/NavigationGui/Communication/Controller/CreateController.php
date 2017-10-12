<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\NavigationGui\Communication\Controller;

use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\NavigationGui\Communication\NavigationGuiCommunicationFactory getFactory()
 */
class CreateController extends AbstractController
{
    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $navigationForm = $this->getFactory()
            ->createNavigationForm()
            ->handleRequest($request);

        if ($navigationForm->isValid()) {
            $navigationTransfer = $navigationForm->getData();
            $navigationTransfer = $this->getFactory()
                ->getNavigationFacade()
                ->createNavigation($navigationTransfer);

            $this->addSuccessMessage(sprintf('Navigation element %d was created successfully.', $navigationTransfer->getIdNavigation()));

            return $this->redirectResponse('/navigation-gui');
        }

        return $this->viewResponse([
            'navigationForm' => $navigationForm->createView(),
        ]);
    }
}
