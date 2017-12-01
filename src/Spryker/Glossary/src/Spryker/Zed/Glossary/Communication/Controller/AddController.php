<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Glossary\Communication\Controller;

use Generated\Shared\Transfer\KeyTranslationTransfer;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\Glossary\Communication\GlossaryCommunicationFactory getFactory()
 * @method \Spryker\Zed\Glossary\Business\GlossaryFacadeInterface getFacade()
 */
class AddController extends AbstractController
{
    const FORM_ADD_TYPE = 'add';

    const MESSAGE_CREATE_SUCCESS = 'Translation %d was created successfully.';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $glossaryForm = $this
            ->getFactory()
            ->createTranslationAddForm();

        $glossaryForm->handleRequest($request);

        if ($glossaryForm->isValid()) {
            $data = $glossaryForm->getData();

            $keyTranslationTransfer = new KeyTranslationTransfer();
            $keyTranslationTransfer->fromArray($data, true);

            $glossaryFacade = $this->getFacade();
            $glossaryFacade->saveGlossaryKeyTranslations($keyTranslationTransfer);
            $idGlossaryKey = $this->getFacade()->getKeyIdentifier($keyTranslationTransfer->getGlossaryKey());

            $this->addSuccessMessage(sprintf(static::MESSAGE_CREATE_SUCCESS, $idGlossaryKey));

            return $this->redirectResponse('/glossary');
        }

        return $this->viewResponse([
            'form' => $glossaryForm->createView(),
        ]);
    }
}
